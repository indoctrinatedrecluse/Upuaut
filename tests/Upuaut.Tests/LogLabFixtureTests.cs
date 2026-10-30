using Upuaut.LogLab;
using Upuaut.LogLab.Models;
using System.Text;

namespace Upuaut.Tests;

public sealed class LogLabFixtureTests
{
    private readonly LogParsingEngine _parser = new();
    private readonly LogAnalysisEngine _analysis = new();

    public static TheoryData<string, LogDocumentFormat, int> StructuredFixtures => new()
    {
        { "09-application-events.ini", LogDocumentFormat.Ini, 3 },
        { "10-service-events.logfmt", LogDocumentFormat.KeyValue, 3 },
        { "11-syslog-mixed-formats.txt", LogDocumentFormat.Syslog, 4 },
        { "12-apache-access.txt", LogDocumentFormat.WebAccess, 4 },
        { "13-windows-event-export.xml", LogDocumentFormat.WindowsEventXml, 3 }
    };

    [Theory]
    [MemberData(nameof(StructuredFixtures))]
    public async Task Structured_fixture_is_auto_detected_and_extracts_records(string fileName, LogDocumentFormat format, int entryCount)
    {
        var document = await ImportFixture(fileName);

        Assert.Equal(format, document.Format);
        Assert.Equal(entryCount, document.Entries.Count);
        Assert.All(document.Entries, entry => Assert.False(string.IsNullOrWhiteSpace(entry.Message)));
        Assert.Empty(document.Warnings);
    }

    [Fact]
    public async Task Ini_fixture_extracts_section_fields_and_scenario_evidence()
    {
        var document = await ImportFixture("09-application-events.ini");
        var warning = Assert.Single(document.Entries, entry => entry.Severity == LogEntrySeverity.Warning);

        Assert.Equal("Indexer", warning.Source);
        Assert.Equal("event.1002", warning.Fields["Section"]);
        Assert.Equal("1002", warning.Fields["event_id"]);
        Assert.Equal(LogScenarioCategory.Network, _analysis.Analyze(document).Entries[warning.Index].Category);
    }

    [Fact]
    public async Task Logfmt_extracts_quoted_message_and_transaction_identifiers()
    {
        var document = await ImportFixture("10-service-events.logfmt");
        var failure = Assert.Single(document.Entries, entry => entry.Severity == LogEntrySeverity.Error);

        Assert.Equal("req-72", failure.Fields["request_id"]);
        Assert.Equal("UPSTREAM_TIMEOUT", failure.Fields["error_code"]);
        Assert.Contains("Job failed after retries", failure.Message);
        Assert.Equal(LogScenarioCategory.Network, _analysis.Analyze(document).Entries[failure.Index].Category);
    }

    [Fact]
    public async Task Syslog_decodes_priority_and_mixed_timestamp_dialects()
    {
        var document = await ImportFixture("11-syslog-mixed-formats.txt");
        var entries = document.Entries;

        Assert.Equal("edge-01", entries[0].Fields["Host"]);
        Assert.Equal("sshd", entries[0].Source);
        Assert.Equal("34", entries[0].Fields["SyslogPriority"]);
        Assert.Equal(LogEntrySeverity.Critical, entries[0].Severity);
        Assert.Equal(LogEntrySeverity.Error, entries[1].Severity);
        Assert.All(entries, entry => Assert.NotNull(entry.Timestamp));
    }

    [Fact]
    public async Task Web_access_records_include_request_status_and_client()
    {
        var document = await ImportFixture("12-apache-access.txt");
        var serverError = document.Entries.First(entry => entry.Fields.GetValueOrDefault("StatusCode") == "503");

        Assert.Equal("192.0.2.19", serverError.Source);
        Assert.Equal("GET", serverError.Fields["Method"]);
        Assert.Equal("/api/report", serverError.Fields["Path"]);
        Assert.Equal(LogEntrySeverity.Error, serverError.Severity);
        Assert.Equal(LogScenarioCategory.Network, _analysis.Analyze(document).Entries[serverError.Index].Category);
    }

    [Fact]
    public async Task Windows_event_export_keeps_repeated_events_and_system_metadata()
    {
        var document = await ImportFixture("13-windows-event-export.xml");
        var failedService = Assert.Single(document.Entries, entry => entry.Fields.GetValueOrDefault("EventId") == "7002");

        Assert.Equal("Example-Service", failedService.Source);
        Assert.Equal("1067", failedService.Fields["ErrorCode"]);
        Assert.Equal(LogEntrySeverity.Error, failedService.Severity);
        Assert.Equal(LogScenarioCategory.Service, _analysis.Analyze(document).Entries[failedService.Index].Category);
        Assert.True(failedService.SourceLineEnd > failedService.SourceLine);
    }

    [Fact]
    public async Task Multiline_crash_details_remain_attached_to_the_error_entry()
    {
        var document = await ImportFixture("14-python-crash-traceback.txt");
        var failure = document.Entries.First(entry => entry.Fields.ContainsKey("ExceptionDetails"));

        Assert.Contains("Traceback", failure.RawText);
        Assert.Contains("KeyError", failure.RawText);
        Assert.True(failure.SourceLineEnd > failure.SourceLine);
        Assert.Equal(LogScenarioCategory.Crash, _analysis.Analyze(document).Entries[failure.Index].Category);
    }

    [Fact]
    public async Task Malformed_json_fixture_is_retained_in_raw_text_mode()
    {
        var document = await ImportFixture("06-malformed-structured.json");

        Assert.Equal(LogDocumentFormat.PlainText, document.Format);
        Assert.Equal("JSON type log file (.json)", document.FileTypeLabel);
        Assert.Contains(document.Warnings, warning => warning.Contains("raw-text mode", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("This fixture is intentionally missing its closing braces", document.OriginalText);
    }

    [Fact]
    public async Task Maintenance_fixture_remains_searchable_even_when_unclassified()
    {
        var document = await ImportFixture("07-unclassified-maintenance.txt");

        Assert.Contains(document.Entries, entry => entry.RawText.Contains("checksum=4f68e7", StringComparison.Ordinal));
        Assert.Equal(document.Entries.Count, _analysis.Analyze(document).EntryCount);
    }

    [Fact]
    public async Task Investigation_reports_include_key_identifiers_and_parser_interpretation()
    {
        var document = await ImportFixture("13-windows-event-export.xml");
        var analysis = _analysis.Analyze(document);
        var exporter = new LogReportExporter();
        var markdown = exporter.ExportMarkdown(document, analysis, []);
        var json = exporter.ExportJson(document, analysis, []);

        Assert.Contains("ErrorCode: 1067", markdown);
        Assert.Contains("Interpretation:", markdown);
        Assert.Contains("\"ErrorCode\": \"1067\"", json);
        Assert.Contains("SourceLineEnd", json);
    }

    [Fact]
    public async Task Unknown_extensions_are_identified_while_content_uses_plain_text_fallback()
    {
        var document = await ImportFixture("17-agent-export.xlog");

        Assert.Equal(LogDocumentFormat.PlainText, document.Format);
        Assert.Equal(".xlog", document.FileExtension);
        Assert.Equal("XLOG type log file (.xlog)", document.FileTypeLabel);
        Assert.Equal(3, document.Entries.Count);
        Assert.Contains("peer state was not ready", document.OriginalText);
        var report = new LogReportExporter().ExportJson(document, _analysis.Analyze(document), []);
        Assert.Contains("XLOG type log file (.xlog)", report);
    }

    [Fact]
    public void Syntax_highlighter_marks_common_log_structure_and_bounds_large_inputs()
    {
        const string sample = "[worker]\ntimestamp=2026-10-30T19:10:00Z level=ERROR error_code=E-19 message=\"retry failed\"";
        var highlighter = new LogSyntaxHighlighter();
        var tokens = highlighter.Tokenize(sample);

        Assert.Contains(tokens, token => token.Kind == LogSyntaxTokenKind.Section);
        Assert.Contains(tokens, token => token.Kind == LogSyntaxTokenKind.Timestamp);
        Assert.Contains(tokens, token => token.Kind == LogSyntaxTokenKind.Key);
        Assert.Contains(tokens, token => token.Kind == LogSyntaxTokenKind.Severity);
        Assert.Contains(tokens, token => token.Kind == LogSyntaxTokenKind.ErrorCode);
        Assert.Contains(tokens, token => token.Kind == LogSyntaxTokenKind.String);
        Assert.Contains(highlighter.Tokenize("{\"ready\": true, \"count\": 3}"), token => token.Kind == LogSyntaxTokenKind.Literal);
        Assert.Contains(highlighter.Tokenize("<Event><Level>2</Level></Event>"), token => token.Kind == LogSyntaxTokenKind.XmlTag);
        Assert.Empty(highlighter.Tokenize(new string('x', LogSyntaxHighlighter.MaximumHighlightCharacters + 1)));
    }

    [Fact]
    public async Task Readable_hex_dump_is_not_rejected_due_to_its_extension()
    {
        var document = await ImportFixture("18-readable-savegame.hex");

        Assert.Equal(LogContentKind.Text, document.ContentKind);
        Assert.Equal("Hex dump file (.hex)", document.FileTypeLabel);
        Assert.Contains("53 41 56 45", document.OriginalText);
        Assert.DoesNotContain(document.Warnings, warning => warning.Contains("non-text or encrypted", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Solution_files_are_kept_as_text_for_raw_inspection()
    {
        var document = await ImportFixture("19-sample-solution.sln");

        Assert.Equal(LogContentKind.Text, document.ContentKind);
        Assert.Equal("Solution file (.sln)", document.FileTypeLabel);
        Assert.Contains("Visual Studio Solution File", document.OriginalText);
        Assert.Equal(LogDocumentFormat.PlainText, document.Format);
    }

    [Fact]
    public async Task Mostly_text_save_content_with_a_few_controls_remains_inspectable()
    {
        var content = "SAVE_VERSION=4\nPLAYER=Recluse\nNOTE=" + new string('a', 256) + "\u0001\n";
        var document = await ImportBytes(Encoding.UTF8.GetBytes(content), ".sav");

        Assert.Equal(LogContentKind.MixedTextAndBinary, document.ContentKind);
        Assert.Contains("PLAYER=Recluse", document.OriginalText);
        Assert.Contains(document.Warnings, warning => warning.Contains("mostly readable text", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Predominantly_text_with_twenty_percent_control_characters_remains_inspectable()
    {
        var content = new string('x', 80) + new string('\u0001', 20);
        var document = await ImportBytes(Encoding.UTF8.GetBytes(content), ".sav");

        Assert.Equal(LogContentKind.MixedTextAndBinary, document.ContentKind);
        Assert.Contains("mostly readable text", Assert.Single(document.Warnings));
        Assert.Contains("xxxx", document.OriginalText);
    }

    [Fact]
    public async Task Source_line_materialization_stops_at_the_structured_entry_limit()
    {
        var content = string.Join('\n', Enumerable.Repeat("2026-10-30T20:00:00Z INFO entry", 200_005));
        var document = await ImportBytes(Encoding.UTF8.GetBytes(content), ".log");

        Assert.Equal(200_000, document.SourceLines.Count);
        Assert.Equal(200_000, document.Entries.Count);
        Assert.Contains(document.Warnings, warning => warning.Contains("physical source lines", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(content, document.OriginalText);
    }

    [Fact]
    public async Task Bomless_utf16_text_is_decoded_before_binary_assessment()
    {
        const string content = "2026-10-30T20:00:00Z INFO save-game checkpoint completed";
        var document = await ImportBytes(Encoding.Unicode.GetBytes(content), ".sav");

        Assert.Equal(LogContentKind.Text, document.ContentKind);
        Assert.Equal("UTF-16 LE (no BOM)", document.DetectedEncoding);
        Assert.Equal(content, document.OriginalText);
        Assert.Equal(LogEntrySeverity.Information, Assert.Single(document.Entries).Severity);
    }

    [Fact]
    public async Task Latin1_text_is_not_mistaken_for_encrypted_binary()
    {
        const string content = "2026-10-30 20:01:00 INFO servicio=pagos mensaje=operación completada con éxito";
        var document = await ImportBytes(Encoding.Latin1.GetBytes(content), ".log");

        Assert.Equal(LogContentKind.Text, document.ContentKind);
        Assert.Equal("ISO-8859-1 fallback", document.DetectedEncoding);
        Assert.Contains("operación", document.OriginalText);
    }

    [Fact]
    public async Task Mostly_binary_save_payload_skips_structured_parsing_but_keeps_a_raw_preview()
    {
        var bytes = new byte[4096];
        new Random(7421).NextBytes(bytes);
        var document = await ImportBytes(bytes, ".sav");

        Assert.Equal(LogContentKind.BinaryLike, document.ContentKind);
        Assert.Equal(LogDocumentFormat.PlainText, document.Format);
        Assert.Contains(document.Warnings, warning => warning.Contains("non-text or encrypted", StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(document.OriginalText);
        Assert.Empty(document.Entries);
        Assert.Equal(0, _analysis.Analyze(document).ClassifiedCount);
        Assert.Empty(new LogSequenceAnalysisEngine().Analyze(document));
    }

    private Task<LogDocument> ImportFixture(string fileName) =>
        _parser.ImportFileAsync(Path.Combine(AppContext.BaseDirectory, "scratch", fileName));

    private async Task<LogDocument> ImportBytes(byte[] bytes, string extension)
    {
        var path = Path.Combine(Path.GetTempPath(), $"upuaut-fixture-{Guid.NewGuid():N}{extension}");
        try
        {
            await File.WriteAllBytesAsync(path, bytes);
            return await _parser.ImportFileAsync(path);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
}
