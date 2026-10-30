using Upuaut.Core.AI;

namespace Upuaut.Tests;

public sealed class AiPromptEngineTests
{
    [Fact]
    public void CompactValue_collapses_whitespace_and_shortens_with_ellipsis()
    {
        Assert.Equal("alpha beta gamma", AiPromptEngine.CompactValue("  alpha\n\tbeta   gamma  ", 200));
        Assert.Equal(string.Empty, AiPromptEngine.CompactValue(null));
        Assert.Equal(string.Empty, AiPromptEngine.CompactValue("   "));

        var shortened = AiPromptEngine.CompactValue(new string('a', 50), 20);

        Assert.Equal(20, shortened.Length);
        Assert.EndsWith("...", shortened, StringComparison.Ordinal);
    }

    [Fact]
    public void CompactText_returns_small_input_verbatim()
    {
        const string small = "line one\nline two";

        Assert.Same(small, AiPromptEngine.CompactText(small, 3_500));
    }

    [Fact]
    public void CompactText_keeps_head_and_tail_and_reports_omitted_middle()
    {
        var text = "HEAD-MARKER\n" + new string('x', 4_000) + "\nTAIL-MARKER";

        var result = AiPromptEngine.CompactText(text, 1_000, 400, 300);

        Assert.True(result.Length < text.Length);
        Assert.Contains("HEAD-MARKER", result);
        Assert.Contains("TAIL-MARKER", result);
        Assert.Contains("omitted from the middle of this unit", result);
        Assert.True(result.Count(c => c == 'x') <= 700);
        Assert.True(result.Length < 1_000 + 200);
    }

    [Fact]
    public void CompactLines_keeps_leading_and_trailing_frames_with_marker()
    {
        var frames = Enumerable.Range(0, 200).Select(index => $"frame-{index}").ToArray();

        var compacted = AiPromptEngine.CompactLines(frames, 25);

        Assert.Equal(21, compacted.Count);
        Assert.Equal("frame-0", compacted[0]);
        Assert.Contains("intermediate frames omitted", compacted[15]);
        Assert.Equal("frame-199", compacted[^1]);
    }

    [Fact]
    public void CompactLines_returns_short_lists_untouched()
    {
        var frames = new[] { "a", "b", "c" };

        Assert.Same(frames, AiPromptEngine.CompactLines(frames, 25));
        Assert.Empty(AiPromptEngine.CompactLines(null, 25));
    }

    [Fact]
    public void CompactPayload_renders_printable_preview_and_flags_truncation()
    {
        var payload = Enumerable.Range(0, 1_024).Select(index => (byte)(index % 256)).ToArray();

        var preview = AiPromptEngine.CompactPayload(payload, 64);

        Assert.Contains("1,024 bytes total", preview);
        Assert.Contains("remaining bytes omitted", preview);
        Assert.True(preview.Split('\n')[0].Length <= 64);
    }

    [Fact]
    public void CompactPayload_reports_missing_payload()
    {
        Assert.Equal("No payload data.", AiPromptEngine.CompactPayload(null));
        Assert.Equal("No payload data.", AiPromptEngine.CompactPayload(Array.Empty<byte>()));
    }

    [Fact]
    public void EnforcePromptBudget_trims_oversized_prompts_below_the_ceiling()
    {
        var prompt = "<selected-log-entry>\n" + new string('y', AiPromptEngine.MaxUserPromptCharacters * 2) + "\n</selected-log-entry>";

        var compacted = AiPromptEngine.EnforcePromptBudget(prompt);

        Assert.True(compacted.Length <= AiPromptEngine.MaxUserPromptCharacters);
        Assert.Contains("<selected-log-entry>", compacted);
        Assert.Contains("</selected-log-entry>", compacted);
    }

    [Fact]
    public void EnforceBudget_leaves_small_requests_unchanged_and_records_a_budget()
    {
        var request = new AiInvestigationRequest(AiAnalysisDomain.Scout, "Frame", "short prompt", "system");

        var guarded = AiPromptEngine.EnforceBudget(request);

        Assert.Equal("short prompt", guarded.UserPrompt);
        Assert.NotNull(guarded.Budget);
        Assert.False(guarded.Budget!.WasCompacted);
        Assert.InRange(guarded.Budget.UtilizationPercent, 0, 100);
        Assert.Contains("full selected context", guarded.Budget.Describe());
        Assert.Equal("No guardrail compaction was required for this request.", guarded.Budget.Explain());
    }

    [Fact]
    public void EnforceBudget_compacts_requests_that_exceed_the_ceiling()
    {
        var prompt = new string('z', AiPromptEngine.MaxUserPromptCharacters + 5_000);
        var request = new AiInvestigationRequest(AiAnalysisDomain.LogLab, "Entry", prompt, "system");

        var guarded = AiPromptEngine.EnforceBudget(request);

        Assert.True(guarded.Budget!.WasCompacted);
        Assert.NotEmpty(guarded.Budget.AppliedGuardrails);
        Assert.True(guarded.UserPrompt.Length <= AiPromptEngine.MaxUserPromptCharacters);
        Assert.Contains("context compacted", guarded.Budget.Describe());
    }

    [Fact]
    public void Log_entry_request_is_complete_for_a_normal_entry()
    {
        var fields = new Dictionary<string, string> { ["EventId"] = "1000", ["Component"] = "Application" };

        var request = AiPromptEngine.BuildLogEntryRequest(
            "2024-05-01 10:00:00 ERROR Application crashed",
            "text",
            "Plain text",
            "app.log",
            42,
            "Error",
            new DateTime(2024, 5, 1, 10, 0, 0, DateTimeKind.Utc),
            fields,
            "Timestamp prefix");

        Assert.Equal(AiAnalysisDomain.LogLab, request.Domain);
        Assert.Contains("Source Line: 42", request.UserPrompt);
        Assert.Contains("EventId: 1000", request.UserPrompt);
        Assert.Contains("Application crashed", request.UserPrompt);
        Assert.Contains("</selected-log-entry>", request.UserPrompt);
        Assert.NotNull(request.Budget);
        Assert.False(request.Budget!.WasCompacted);
    }

    [Fact]
    public void Packet_request_sends_only_a_bounded_payload_preview()
    {
        var payload = new byte[4_096];
        for (var index = 0; index < payload.Length; index++) payload[index] = (byte)('A' + (index % 26));
        var details = Enumerable.Range(0, 200)
            .Select(index => ("TCP", $"field-{index}", new string('v', 400)))
            .ToArray();

        var request = AiPromptEngine.BuildPacketRequest(
            12, "TLSv1.3", "TCP", "10.0.0.5", 51_234, "93.184.216.34", 443, "chrome.exe", 4_242, 1_450,
            "Application Data", payload, details, "Encrypted session", new[] { "Verify certificate chain" });

        Assert.Equal(AiAnalysisDomain.Scout, request.Domain);
        Assert.Contains("Frame Number: #12", request.UserPrompt);
        Assert.Contains("chrome.exe", request.UserPrompt);
        Assert.Contains("further header fields omitted", request.UserPrompt);
        Assert.Contains("4,096 bytes total", request.UserPrompt);
        Assert.DoesNotContain(new string('A', 300), request.UserPrompt);
        Assert.NotNull(request.Budget);
        Assert.True(request.Budget!.WasCompacted);
        Assert.Contains("payload-preview", request.Budget.Explain());
    }

    [Fact]
    public void Crash_request_compacts_only_oversized_call_stacks()
    {
        var frames = Enumerable.Range(0, 80).Select(index => $"0x{index:x4} module!function+0x{index:x2}").ToArray();

        var request = AiPromptEngine.BuildCrashArtifactRequest(
            "Minidump", "notepad.exe crashed", "x64", "Windows 11", DateTimeOffset.UnixEpoch, 4_242,
            "0xC0000005", "Access violation", "ntdll.dll", "Thread 0", frames,
            new[] { "Symbol resolution was unavailable." }, null);

        Assert.Equal(AiAnalysisDomain.CrashForensics, request.Domain);
        Assert.Contains("Call Stack Frames", request.UserPrompt);
        Assert.Contains("intermediate frames omitted", request.UserPrompt);
        Assert.Contains("Symbol resolution was unavailable.", request.UserPrompt);
        Assert.NotNull(request.Budget);
        Assert.True(request.Budget!.WasCompacted);
        Assert.Contains("Call stack:", request.Budget.Explain());
    }

    [Fact]
    public void Legacy_entry_request_guards_untrusted_text()
    {
        var request = AiPromptEngine.BuildLegacyEntryRequest(new string('q', AiPromptEngine.MaxLegacyEntryCharacters + 2_000), "app.log");

        Assert.Equal(AiAnalysisDomain.LogLab, request.Domain);
        Assert.Contains("<selected-log-entry>", request.UserPrompt);
        Assert.Contains("omitted from the middle of this unit", request.UserPrompt);
        Assert.True(request.UserPrompt.Length <= AiPromptEngine.MaxUserPromptCharacters);
        Assert.True(request.Budget!.WasCompacted);
    }
}
