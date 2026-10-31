using System.Text;
using System.Text.Json;

namespace Upuaut.Core.AI;

/// <summary>
/// Extracts assistant text from provider responses.
/// <para>
/// Providers disagree on the response shape: chat completions nest text under
/// <c>choices[].message.content</c> (a string or an array of content parts), reasoning models put
/// their only readable text in <c>reasoning_content</c>, Gemini uses
/// <c>candidates[].content.parts[].text</c> (with <c>thought</c> parts mixed in), local
/// OpenAI-compatible servers answer with <c>message.content</c> or <c>response</c>, gateways wrap the
/// provider payload in <c>data</c>/<c>result</c>, and some servers stream Server-Sent Events even
/// when <c>stream</c> was disabled. This parser accepts every one of those shapes, ignores empty
/// parts, falls back to reasoning text, unwraps a whole-response Markdown fence, and reports an
/// actionable error — including the provider's stop reason — when a 200 response truly contains no
/// readable answer.
/// </para>
/// </summary>
public static class AiResponseParser
{
    /// <summary>Maximum assistant characters handed back to the UI; longer text is clipped with a marker.</summary>
    public const int MaximumAssistantCharacters = 200_000;

    /// <summary>Maximum payload inspected; larger bodies are clipped before parsing.</summary>
    public const int MaximumPayloadCharacters = 2_000_000;

    private const int MaximumCollectionDepth = 5;
    private const int MaximumCollectedValues = 64;
    private const int MaximumDiagnosticCharacters = 300;

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        MaxDepth = 64,
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    /// <summary>Properties that directly carry assistant-visible text, in provider priority order.</summary>
    private static readonly string[] TextKeys = { "content", "text", "output_text", "response", "completion", "answer", "generated_text" };

    /// <summary>Properties that carry model reasoning when a provider withholds the final answer.</summary>
    private static readonly string[] ReasoningKeys = { "reasoning_content", "reasoning", "thinking", "analysis" };

    /// <summary>Properties that may wrap another provider payload one or more levels deep.</summary>
    private static readonly string[] ContainerKeys = { "data", "result", "response", "output", "message", "delta", "choices", "candidates", "content", "parts", "body", "payload" };

    /// <summary>
    /// Reads the assistant's answer from a provider response body.
    /// </summary>
    /// <param name="body">Raw response body (JSON, Server-Sent Events, JSON Lines, or plain text).</param>
    /// <param name="provider">Configured provider, used for response shape priority and error wording.</param>
    /// <exception cref="InvalidDataException">The body contains no readable assistant text.</exception>
    public static string ExtractAssistantText(string? body, AiProvider provider)
    {
        var label = ProviderLabel(provider);
        var payload = NormalizePayload(body);
        if (payload.Length == 0)
            throw new InvalidDataException($"The {label} response was empty. Check the endpoint, the model's access, and the provider status, then retry manually.");

        if (!LooksLikeJson(payload))
        {
            if (ReadStreamedText(payload, out var streamed, out var wasStream))
            {
                if (!wasStream) return Complete(payload);
                if (streamed.Length > 0) return Complete(streamed);
                throw new InvalidDataException($"{label} streamed a response that contained no readable assistant text. Confirm the selected model writes chat text, then retry manually.");
            }

            if (LooksLikeHtml(payload))
                throw new InvalidDataException($"{label} returned a web page instead of an API response. Point the endpoint at the chat API (for example https://api.deepseek.com/chat/completions) instead of a site homepage or proxy landing page.");
            return Complete(payload);
        }

        var document = TryParseDocument(payload) ?? TryParseDocument(ExtractFirstJsonBlock(payload));
        if (document is null)
        {
            if (ReadStreamedText(payload, out var streamedText, out var streamedBody) && streamedBody && streamedText.Length > 0) return Complete(streamedText);
            throw new InvalidDataException($"{label} returned JSON that could not be parsed. Check the endpoint URL, any proxy in front of the provider, and the provider response format.");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                var arrayVisible = new List<string>();
                var arrayReasoning = new List<string>();
                foreach (var item in root.EnumerateArray())
                    CollectAssistantText(item, provider, arrayVisible, arrayReasoning, 0);

                var arrayText = Join(arrayVisible, arrayReasoning);
                if (arrayText.Length > 0) return Complete(arrayText);
                throw DescribeNoText(label, root, provider);
            }

            if (root.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException($"{label} returned JSON in an unexpected shape. Confirm the endpoint points at the chat API and that the selected model is available.");

            var providerError = ReadProviderError(root);
            if (providerError.Length > 0) throw new InvalidDataException(providerError);

            var visible = new List<string>();
            var reasoning = new List<string>();
            CollectAssistantText(root, provider, visible, reasoning, 0);

            var text = Join(visible, reasoning);
            if (text.Length > 0) return Complete(text);
            throw DescribeNoText(label, root, provider);
        }
    }
    /// <summary>
    /// Reads a provider error message embedded in a failed response body. Returns an empty string
    /// when the body holds no recognisable error text.
    /// </summary>
    public static string ExtractProviderErrorMessage(string? body)
    {
        using var document = TryParseDocument(NormalizePayload(body));
        if (document is null) return string.Empty;

        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return string.Empty;
        if (root.TryGetProperty("error", out var error))
        {
            var formatted = FormatProviderError(error);
            if (formatted.Length > 0) return formatted;
        }

        if (root.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.String)
            return Clip(message.GetString() ?? string.Empty);
        if (root.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.String)
            return Clip(detail.GetString() ?? string.Empty);
        return string.Empty;
    }

    private static void CollectAssistantText(JsonElement element, AiProvider provider, List<string> visible, List<string> reasoning, int depth)
    {
        if (depth > MaximumCollectionDepth || element.ValueKind != JsonValueKind.Object) return;

        // Gemini marks internal reasoning parts with "thought": true; they never count as an answer.
        var isThought = element.TryGetProperty("thought", out var thoughtFlag) && thoughtFlag.ValueKind == JsonValueKind.True;

        // Chat completions (DeepSeek, OpenAI, OpenAI-compatible gateways, local servers): choices[].
        if (element.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array)
        {
            foreach (var choice in choices.EnumerateArray())
            {
                if (choice.ValueKind != JsonValueKind.Object) continue;
                if (choice.TryGetProperty("message", out var message)) CollectMessageText(message, visible, reasoning);
                if (choice.TryGetProperty("delta", out var delta)) CollectMessageText(delta, visible, reasoning);
                AddTextValues(choice, "text", visible); // legacy text-completions shape
            }
        }

        // Gemini: candidates[].content.parts[].text, where thought parts are reasoning.
        if (element.TryGetProperty("candidates", out var candidates) && candidates.ValueKind == JsonValueKind.Array)
        {
            foreach (var candidate in candidates.EnumerateArray())
            {
                if (candidate.ValueKind != JsonValueKind.Object) continue;
                if (!candidate.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object) continue;
                if (!content.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array) continue;

                foreach (var part in parts.EnumerateArray())
                {
                    if (part.ValueKind != JsonValueKind.Object) continue;
                    var isThoughtPart = part.TryGetProperty("thought", out var partThought) && partThought.ValueKind == JsonValueKind.True;
                    foreach (var value in ReadTextValues(part, "text")) Add(isThoughtPart ? reasoning : visible, value);
                }
            }
        }

        foreach (var key in TextKeys)
        {
            if (!element.TryGetProperty(key, out _)) continue;
            var target = isThought ? reasoning : visible;
            AddTextValues(element, key, target);
        }
        foreach (var key in ReasoningKeys) AddTextValues(element, key, reasoning);

        foreach (var key in ContainerKeys)
        {
            if (!element.TryGetProperty(key, out var child)) continue;
            if (child.ValueKind == JsonValueKind.Object)
            {
                CollectAssistantText(child, provider, visible, reasoning, depth + 1);
                continue;
            }
            if (child.ValueKind != JsonValueKind.Array) continue;
            foreach (var item in child.EnumerateArray())
                if (item.ValueKind == JsonValueKind.Object) CollectAssistantText(item, provider, visible, reasoning, depth + 1);
        }
    }
    private static void CollectMessageText(JsonElement message, List<string> visible, List<string> reasoning)
    {
        if (message.ValueKind != JsonValueKind.Object) return;
        AddTextValues(message, "content", visible);
        foreach (var key in ReasoningKeys) AddTextValues(message, key, reasoning);
    }

    private static void AddTextValues(JsonElement element, string propertyName, List<string> target)
    {
        if (element.ValueKind != JsonValueKind.Object) return;
        foreach (var value in ReadTextValues(element, propertyName)) Add(target, value);
    }

    private static IEnumerable<string> ReadTextValues(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(propertyName, out var value)) yield break;

        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                yield return value.GetString() ?? string.Empty;
                break;

            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String) { yield return item.GetString() ?? string.Empty; continue; }
                    if (item.ValueKind != JsonValueKind.Object) continue;
                    if (item.TryGetProperty("text", out var partText) && partText.ValueKind == JsonValueKind.String) { yield return partText.GetString() ?? string.Empty; continue; }
                    if (item.TryGetProperty("content", out var partContent) && partContent.ValueKind == JsonValueKind.String) yield return partContent.GetString() ?? string.Empty;
                }
                break;

            case JsonValueKind.Object:
                if (value.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String) { yield return text.GetString() ?? string.Empty; break; }
                if (value.TryGetProperty("content", out var nested) && nested.ValueKind == JsonValueKind.String) yield return nested.GetString() ?? string.Empty;
                break;
        }
    }

    private static void Add(List<string> target, string? value)
    {
        if (target.Count >= MaximumCollectedValues) return;
        var trimmed = value?.Trim();
        if (string.IsNullOrEmpty(trimmed)) return;
        if (target.Contains(trimmed, StringComparer.Ordinal)) return;
        target.Add(trimmed);
    }

    private static string Join(List<string> visible, List<string> reasoning)
    {
        if (visible.Count > 0) return StripNoise(string.Join("\n\n", visible));
        if (reasoning.Count > 0) return StripNoise(string.Join("\n\n", reasoning));
        return string.Empty;
    }
    /// <summary>
    /// Reads Server-Sent Events or JSON Lines chunks. Returns <c>false</c> when the body is not a
    /// stream; <paramref name="wasStream"/> reports a stream that carried no readable text so the
    /// caller can raise a diagnostic instead of echoing protocol frames to the operator.
    /// </summary>
    private static bool ReadStreamedText(string payload, out string text, out bool wasStream)
    {
        text = string.Empty;
        wasStream = false;
        if (payload.IndexOf("data:", StringComparison.OrdinalIgnoreCase) < 0 && payload.IndexOf('\n') < 0) return false;

        var deltas = new StringBuilder();
        var messages = new List<string>();
        var reasoning = new List<string>();
        var parsedAny = false;

        foreach (var rawLine in payload.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("id:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("retry:", StringComparison.OrdinalIgnoreCase)) continue;
            if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) line = line[5..].Trim();
            if (line.Length == 0 || line.Equals("[DONE]", StringComparison.Ordinal)) continue;
            if (line[0] is not ('{' or '[')) continue;

            var chunk = TryParseDocument(line);
            if (chunk is null) continue;
            using (chunk)
            {
                parsedAny = true;
                wasStream = true;
                var root = chunk.RootElement;
                if (root.ValueKind == JsonValueKind.Array)
                    foreach (var item in root.EnumerateArray()) CollectStreamChunk(item, deltas, messages, reasoning);
                else
                    CollectStreamChunk(root, deltas, messages, reasoning);
            }
        }

        if (!parsedAny) return false;

        var joinedDeltas = StripNoise(deltas.ToString());
        if (joinedDeltas.Length > 0) { text = joinedDeltas; return true; }

        var joinedMessages = Join(messages, reasoning);
        if (joinedMessages.Length > 0) { text = joinedMessages; return true; }
        return true;
    }

    private static void CollectStreamChunk(JsonElement chunk, StringBuilder deltas, List<string> messages, List<string> reasoning)
    {
        if (chunk.ValueKind != JsonValueKind.Object) return;

        if (chunk.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array)
        {
            foreach (var choice in choices.EnumerateArray())
            {
                if (choice.ValueKind != JsonValueKind.Object) continue;
                if (choice.TryGetProperty("delta", out var delta) && delta.ValueKind == JsonValueKind.Object)
                {
                    AppendDelta(deltas, delta, "content");
                    foreach (var key in ReasoningKeys) AppendDelta(deltas, delta, key);
                }
                if (choice.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.Object)
                    foreach (var value in ReadTextValues(message, "content")) Add(messages, value);
                foreach (var value in ReadTextValues(choice, "text")) Add(messages, value);
            }
        }

        if (chunk.TryGetProperty("candidates", out var candidates) && candidates.ValueKind == JsonValueKind.Array)
        {
            foreach (var candidate in candidates.EnumerateArray())
            {
                if (candidate.ValueKind != JsonValueKind.Object) continue;
                if (!candidate.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object) continue;
                if (!content.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array) continue;
                foreach (var part in parts.EnumerateArray())
                {
                    if (part.ValueKind != JsonValueKind.Object) continue;
                    var isThought = part.TryGetProperty("thought", out var thought) && thought.ValueKind == JsonValueKind.True;
                    foreach (var value in ReadTextValues(part, "text"))
                    {
                        if (isThought) Add(reasoning, value);
                        else deltas.Append(value);
                    }
                }
            }
        }

        // Anthropic-style content_block_delta and Ollama-style streaming responses.
        if (chunk.TryGetProperty("delta", out var streamDelta) && streamDelta.ValueKind == JsonValueKind.Object)
            foreach (var value in ReadTextValues(streamDelta, "text")) deltas.Append(value);
        if (chunk.TryGetProperty("message", out var streamMessage) && streamMessage.ValueKind == JsonValueKind.Object)
            foreach (var value in ReadTextValues(streamMessage, "content")) Add(messages, value);
        foreach (var value in ReadTextValues(chunk, "response")) deltas.Append(value);
    }

    private static void AppendDelta(StringBuilder deltas, JsonElement element, string propertyName)
    {
        foreach (var value in ReadTextValues(element, propertyName)) deltas.Append(value);
    }
    private static InvalidDataException DescribeNoText(string label, JsonElement root, AiProvider provider)
    {
        var block = ReadFirstString(root, "blockReason", "block_reason");
        if (block is null && root.TryGetProperty("promptFeedback", out var feedback))
            block = ReadFirstString(feedback, "blockReason", "block_reason");
        if (block is null && root.TryGetProperty("prompt_feedback", out var snakeFeedback))
            block = ReadFirstString(snakeFeedback, "block_reason", "blockReason");
        if (block is not null)
            return new InvalidDataException($"{label} blocked the request ({Clip(block)}). Review the selected unit and retry only if sharing it is appropriate.");

        var refusal = FindFirstString(root, "refusal");
        if (refusal is not null)
            return new InvalidDataException($"The provider declined the request: {Clip(refusal)}");

        if (ContainsToolCalls(root))
            return new InvalidDataException($"{label} answered only with tool or function calls and no readable text. Select a model that replies in chat text, then retry.");

        var stopReason = DescribeStopReason(root);
        if (IsOutputLimitStop(stopReason))
            return new InvalidDataException($"{label} stopped at the model's output token limit before writing an answer (finish reason: {Clip(stopReason!)}). Raise the model's output limit or review a shorter unit, then retry manually. Reasoning models spend part of that limit on internal reasoning.");

        if (provider == AiProvider.Gemini && stopReason is not null)
            return new InvalidDataException($"Gemini stopped without readable text (finish reason: {Clip(stopReason)}). Confirm the selected model returns text parts and that safety filters did not stop the answer.");

        if (stopReason is not null)
            return new InvalidDataException($"{label} finished with \"{Clip(stopReason)}\" but returned no readable assistant text. Confirm the selected model writes chat text and that the endpoint points at the chat completions path.");

        return new InvalidDataException($"{label} returned a valid response but no readable assistant text. Confirm the selected model writes chat text, and check that the endpoint and model identifier match the provider.");
    }

    private static string? DescribeStopReason(JsonElement root)
    {
        var direct = ReadFirstString(root, "finish_reason", "finishReason", "stop_reason", "stopReason");
        if (direct is not null) return direct;

        foreach (var key in new[] { "choices", "candidates" })
        {
            if (!root.TryGetProperty(key, out var array) || array.ValueKind != JsonValueKind.Array) continue;
            foreach (var item in array.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                var nested = ReadFirstString(item, "finish_reason", "finishReason", "stop_reason", "stopReason");
                if (nested is not null) return nested;
            }
        }

        return null;
    }

    private static bool IsOutputLimitStop(string? stopReason)
    {
        if (stopReason is null) return false;
        var normalized = stopReason.Replace("-", "_", StringComparison.Ordinal).Replace(" ", "_", StringComparison.Ordinal).ToLowerInvariant();
        return normalized is "length" or "max_tokens" or "maxtokens" or "maximum_tokens" or "model_length" or "max_output_tokens" or "incomplete";
    }
    private static bool ContainsToolCalls(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;
        if (HasNonEmptyArray(root, "tool_calls") || HasNonEmptyArray(root, "toolCalls")) return true;
        if (root.TryGetProperty("function_call", out var call) && call.ValueKind == JsonValueKind.Object) return true;
        if (!root.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array) return false;

        foreach (var choice in choices.EnumerateArray())
        {
            if (choice.ValueKind != JsonValueKind.Object) continue;
            if (!choice.TryGetProperty("message", out var message) || message.ValueKind != JsonValueKind.Object) continue;
            if (HasNonEmptyArray(message, "tool_calls") || HasNonEmptyArray(message, "toolCalls")) return true;
            if (message.TryGetProperty("function_call", out var functionCall) && functionCall.ValueKind == JsonValueKind.Object) return true;
        }

        return false;
    }

    private static bool HasNonEmptyArray(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.Array && value.GetArrayLength() > 0;

    private static string? FindFirstString(JsonElement root, string propertyName)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;
        var direct = ReadFirstString(root, propertyName);
        if (direct is not null) return direct;

        if (!root.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array) return null;
        foreach (var choice in choices.EnumerateArray())
        {
            if (choice.ValueKind != JsonValueKind.Object) continue;
            if (!choice.TryGetProperty("message", out var message) || message.ValueKind != JsonValueKind.Object) continue;
            var nested = ReadFirstString(message, propertyName);
            if (nested is not null) return nested;
        }

        return null;
    }

    private static string? ReadFirstString(JsonElement element, params string[] propertyNames)
    {
        if (element.ValueKind != JsonValueKind.Object) return null;
        foreach (var name in propertyNames)
            if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString()))
                return value.GetString()!.Trim();
        return null;
    }

    private static string ReadProviderError(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return string.Empty;
        if (root.TryGetProperty("error", out var error))
        {
            var formatted = FormatProviderError(error);
            if (formatted.Length > 0) return formatted;
        }

        // Some gateways answer 200 with {"type":"error","message":"..."} instead of an error status.
        if (root.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString()!.Equals("error", StringComparison.OrdinalIgnoreCase))
        {
            var message = ReadFirstString(root, "message", "detail");
            if (message is not null) return Clip(message);
        }

        return string.Empty;
    }

    private static string FormatProviderError(JsonElement error)
    {
        if (error.ValueKind == JsonValueKind.String) return Clip(error.GetString() ?? string.Empty);
        if (error.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in error.EnumerateArray())
            {
                var formatted = FormatProviderError(item);
                if (formatted.Length > 0) return formatted;
            }
            return string.Empty;
        }
        if (error.ValueKind != JsonValueKind.Object) return string.Empty;

        var message = error.TryGetProperty("message", out var messageElement)
            ? messageElement.ValueKind == JsonValueKind.String ? Clip(messageElement.GetString() ?? string.Empty) : FormatProviderError(messageElement)
            : string.Empty;
        var code = error.TryGetProperty("code", out var codeElement) && (codeElement.ValueKind == JsonValueKind.String || codeElement.ValueKind == JsonValueKind.Number)
            ? Clip(codeElement.ToString())
            : ReadFirstString(error, "type", "status") ?? string.Empty;
        return string.Join(" · ", new[] { code, message }.Where(value => !string.IsNullOrWhiteSpace(value)));
    }
    private static JsonDocument? TryParseDocument(string? json)
    {
        var trimmed = (json ?? string.Empty).Trim().TrimStart('\uFEFF').Trim();
        if (trimmed.Length == 0) return null;
        try { return JsonDocument.Parse(trimmed, DocumentOptions); }
        catch (JsonException) { return null; }
    }

    /// <summary>Returns the first balanced JSON object or array embedded in a larger text body.</summary>
    private static string? ExtractFirstJsonBlock(string payload)
    {
        var start = -1;
        for (var index = 0; index < payload.Length; index++)
        {
            if (payload[index] is '{' or '[') { start = index; break; }
        }
        if (start < 0) return null;

        var open = payload[start];
        var close = open == '{' ? '}' : ']';
        var depth = 0;
        var inString = false;
        var escaped = false;

        for (var index = start; index < payload.Length; index++)
        {
            var character = payload[index];
            if (inString)
            {
                if (escaped) { escaped = false; continue; }
                if (character == '\\') { escaped = true; continue; }
                if (character == '"') inString = false;
                continue;
            }

            if (character == '"') { inString = true; continue; }
            if (character == open) depth++;
            else if (character == close)
            {
                depth--;
                if (depth == 0) return payload[start..(index + 1)];
            }
        }

        return null;
    }

    private static bool LooksLikeJson(string payload) => payload[0] is '{' or '[';

    private static bool LooksLikeHtml(string payload)
    {
        var trimmed = payload.TrimStart();
        if (trimmed.Length == 0 || trimmed[0] != '<') return false;
        return trimmed.StartsWith("<!doctype", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Contains("<html", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Contains("<body", StringComparison.OrdinalIgnoreCase);
    }
    private static string NormalizePayload(string? body)
    {
        var value = body ?? string.Empty;
        if (value.Length > MaximumPayloadCharacters) value = value[..MaximumPayloadCharacters];
        return StripNoise(value);
    }

    private static string StripNoise(string value)
    {
        if (value.Length == 0) return string.Empty;

        var normalized = value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var cleaned = new StringBuilder(normalized.Length);
        var newlineRun = 0;
        foreach (var character in normalized)
        {
            if (character is '\uFEFF' or '\u200B' or '\u200C' or '\u200D' or '\u2060' or '\0') continue;
            if (character == '\n')
            {
                newlineRun++;
                if (newlineRun > 2) continue;
            }
            else
            {
                newlineRun = 0;
            }

            cleaned.Append(character);
        }

        return cleaned.ToString().Trim();
    }

    private static string Complete(string text)
    {
        var cleaned = UnwrapMarkdownFence(text.Trim());
        if (cleaned.Length <= MaximumAssistantCharacters) return cleaned;
        const string marker = "\n\n[... AI response truncated at the display limit ...]";
        return cleaned[..(MaximumAssistantCharacters - marker.Length)].TrimEnd() + marker;
    }

    private static string UnwrapMarkdownFence(string text)
    {
        if (!text.StartsWith("```", StringComparison.Ordinal) || !text.EndsWith("```", StringComparison.Ordinal) || text.Length < 7) return text;
        var firstLineEnd = text.IndexOf('\n');
        if (firstLineEnd < 0 || firstLineEnd > 24) return text;
        var language = text[3..firstLineEnd].Trim();
        if (language.Length > 0 && !language.Equals("markdown", StringComparison.OrdinalIgnoreCase) && !language.Equals("md", StringComparison.OrdinalIgnoreCase)) return text;
        return text[(firstLineEnd + 1)..^3].Trim();
    }

    private static string Clip(string value)
    {
        var clean = new string((value ?? string.Empty).Where(character => !char.IsControl(character) || character is '\r' or '\n' or '\t').ToArray());
        clean = string.Join(' ', clean.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return clean.Length <= MaximumDiagnosticCharacters ? clean : clean[..(MaximumDiagnosticCharacters - 3)] + "...";
    }

    private static string ProviderLabel(AiProvider provider) => provider switch
    {
        AiProvider.DeepSeek => "DeepSeek",
        AiProvider.Gemini => "Gemini",
        _ => "The OpenAI-compatible provider"
    };
}
