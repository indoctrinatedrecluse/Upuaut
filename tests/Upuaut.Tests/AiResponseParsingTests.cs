using System.Text.Json;
using Upuaut.Core.AI;

namespace Upuaut.Tests;

public sealed class AiResponseParsingTests
{
    [Fact]
    public void Chat_completions_string_content_is_returned()
    {
        const string body = """
            {"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"### Summary"},"finish_reason":"stop"}]}
            """;

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.Equal("### Summary", text);
    }

    [Fact]
    public void Chat_completions_content_parts_are_joined_and_empty_parts_ignored()
    {
        const string body = """
            {"choices":[{"index":0,"message":{"role":"assistant","content":[{"type":"text","text":"### Summary"},{"type":"text","text":""},{"type":"text","text":"- Two leads"}]},"finish_reason":"stop"}]}
            """;

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.StartsWith("### Summary", text, StringComparison.Ordinal);
        Assert.Contains("- Two leads", text, StringComparison.Ordinal);
        Assert.DoesNotContain("\n\n\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Reasoning_only_response_falls_back_to_reasoning_text()
    {
        const string body = """
            {"choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning_content":"### Likely cause"},"finish_reason":"stop"}]}
            """;

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.Equal("### Likely cause", text);
    }

    [Fact]
    public void Output_limit_stop_reports_an_actionable_error()
    {
        const string body = """
            {"choices":[{"index":0,"message":{"role":"assistant","content":null},"finish_reason":"length"}]}
            """;

        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek));

        Assert.Contains("output token limit", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("length", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Legacy_choice_text_and_object_wrappers_are_read()
    {
        const string legacy = """
            {"choices":[{"index":0,"text":"### Legacy completion"}]}
            """;
        const string wrapped = """
            {"data":{"result":{"message":{"role":"assistant","content":"### Wrapped by a gateway"}}}}
            """;
        const string local = """
            {"model":"qwen2.5","message":{"role":"assistant","content":"### Local server"}}
            """;
        const string ollama = """
            {"model":"llama3","response":"### Ollama response","done":true}
            """;

        Assert.Equal("### Legacy completion", AiResponseParser.ExtractAssistantText(legacy, AiProvider.DeepSeek));
        Assert.Equal("### Wrapped by a gateway", AiResponseParser.ExtractAssistantText(wrapped, AiProvider.DeepSeek));
        Assert.Equal("### Local server", AiResponseParser.ExtractAssistantText(local, AiProvider.DeepSeek));
        Assert.Equal("### Ollama response", AiResponseParser.ExtractAssistantText(ollama, AiProvider.DeepSeek));
    }

    [Fact]
    public void Responses_api_output_array_is_read()
    {
        const string body = """
            {"status":"completed","output":[{"type":"reasoning","content":[]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"### Checklist"}]}]}
            """;

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.Equal("### Checklist", text);
    }

    [Fact]
    public void Server_sent_events_are_concatenated()
    {
        const string body = """
            data: {"id":"1","choices":[{"index":0,"delta":{"role":"assistant","content":"### Summary"},"finish_reason":null}]}

            data: {"id":"1","choices":[{"index":0,"delta":{"content":"\n- First lead"},"finish_reason":null}]}

            data: [DONE]
            """;

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.StartsWith("### Summary", text, StringComparison.Ordinal);
        Assert.Contains("- First lead", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Gemini_candidates_text_is_read_and_thought_parts_are_not_preferred()
    {
        const string thoughtOnly = """
            {"candidates":[{"content":{"role":"model","parts":[{"thought":true,"text":"### Internal plan"}]},"finishReason":"STOP"}]}
            """;
        const string withAnswer = """
            {"candidates":[{"content":{"role":"model","parts":[{"thought":true,"text":"### Internal plan"},{"text":"### Event review"}]},"finishReason":"STOP"}]}
            """;

        Assert.Equal("### Internal plan", AiResponseParser.ExtractAssistantText(thoughtOnly, AiProvider.Gemini));
        Assert.Equal("### Event review", AiResponseParser.ExtractAssistantText(withAnswer, AiProvider.Gemini));
    }

    [Fact]
    public void Gemini_blocked_candidate_is_explained()
    {
        const string body = """
            {"promptFeedback":{"blockReason":"SAFETY"},"candidates":[]}
            """;

        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText(body, AiProvider.Gemini));

        Assert.Contains("SAFETY", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Plain_markdown_body_is_returned_unchanged()
    {
        const string body = """
            # Event review

            - Channel: System
            - Event ID: 1000
            """;

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.StartsWith("# Event review", text, StringComparison.Ordinal);
        Assert.Contains("- Event ID: 1000", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_body_is_rejected_with_endpoint_guidance()
    {
        const string body = "<!doctype html><html><body><h1>Welcome</h1></body></html>";

        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek));

        Assert.Contains("web page", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("endpoint", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Whole_response_markdown_fence_is_unwrapped_but_inner_fences_survive()
    {
        const string fenced = """
            ```markdown
            ### Summary

            - Lead one
            ```
            """;
        const string withCode = """
            ### Summary

            ```powershell
            Get-WinEvent -LogName System
            ```
            """;

        Assert.Equal("### Summary\n\n- Lead one", AiResponseParser.ExtractAssistantText(fenced, AiProvider.DeepSeek));
        Assert.Contains("```powershell", AiResponseParser.ExtractAssistantText(withCode, AiProvider.DeepSeek), StringComparison.Ordinal);
    }

    [Fact]
    public void Provider_error_object_in_a_success_body_is_surfaced()
    {
        const string body = """
            {"error":{"message":"Insufficient balance","type":"insufficient_quota","code":"402"}}
            """;

        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek));

        Assert.Contains("Insufficient balance", error.Message, StringComparison.Ordinal);
        Assert.Contains("402", error.Message, StringComparison.Ordinal);
        Assert.Equal("402 · Insufficient balance", AiResponseParser.ExtractProviderErrorMessage(body));
    }

    [Fact]
    public void Tool_call_only_response_is_explained()
    {
        const string body = """
            {"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}
            """;

        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek));

        Assert.Contains("tool", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Empty_body_is_explained()
    {
        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText("   ", AiProvider.DeepSeek));

        Assert.Contains("empty", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unparsable_json_is_explained()
    {
        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText("{\"choices\":[{\"message\":", AiProvider.DeepSeek));

        Assert.Contains("could not be parsed", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Structured_response_without_any_text_is_explained()
    {
        const string body = """
            {"id":"x","object":"chat.completion","model":"deepseek-chat","usage":{"prompt_tokens":10,"completion_tokens":0}}
            """;

        var error = Assert.Throws<InvalidDataException>(() => AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek));

        Assert.Contains("no readable assistant text", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("model", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Oversized_assistant_text_is_clipped_with_a_marker()
    {
        var body = "{\"choices\":[{\"message\":{\"content\":\"" + new string('a', AiResponseParser.MaximumAssistantCharacters + 500) + "\"}}]}";

        var text = AiResponseParser.ExtractAssistantText(body, AiProvider.DeepSeek);

        Assert.Equal(AiResponseParser.MaximumAssistantCharacters, text.Length);
        Assert.Contains("truncated", text, StringComparison.OrdinalIgnoreCase);
    }

    // __APPEND__
}
