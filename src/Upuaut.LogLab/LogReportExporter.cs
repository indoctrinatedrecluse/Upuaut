using System.Text;
using System.Text.Json;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public sealed class LogReportExporter : ILogReportExporter
{
    private const int MaximumFindingsInReport = 10_000;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string ExportMarkdown(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences, LogTimelineReport? timeline = null, LogSequenceAnalysisOptions? sequenceOptions = null, LogReportOptions? options = null)
    {
        options ??= new LogReportOptions();
        sequenceOptions ??= new LogSequenceAnalysisOptions();
        var output = new StringBuilder();
        output.AppendLine("# Upuaut Log Lab Investigation Report").AppendLine();
        output.AppendLine($"- **Source:** {Escape(document.FileName)}").AppendLine($"- **Generated:** {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}")
            .AppendLine($"- **File type:** {Escape(document.FileTypeLabel)} · **Content parser:** {document.Format} · **Content assessment:** {document.ContentKind} · **Encoding:** {Escape(document.DetectedEncoding)} · **Size:** {document.ByteLength:N0} bytes");
        output.AppendLine($"- **Sequence review:** {Math.Clamp(sequenceOptions.WindowMinutes, 1, 1440)} minute window; same component only: {(sequenceOptions.SameComponentOnly ? "yes" : "no")}");
        if (options.IncludeSummary) output.AppendLine($"- **Entries:** {analysis.EntryCount:N0} · **Errors:** {analysis.ErrorCount:N0} · **Warnings:** {analysis.WarningCount:N0}");
        output.AppendLine("- **Interpretation:** scenario labels and sequence groupings are rule-based review aids, not root-cause conclusions.").AppendLine();
        if (options.IncludeCategorySummary)
        {
            output.AppendLine("## Scenario summary").AppendLine().AppendLine("| Category | Entries |").AppendLine("|---|---:|");
            foreach (var category in analysis.CategoryCounts) output.AppendLine($"| {category.Category} | {category.Count:N0} |");
            output.AppendLine();
        }
        if (options.IncludeTimeline && timeline is not null)
        {
            output.AppendLine("## Timeline trend").AppendLine().AppendLine($"UTC bucket interval: {timeline.EffectiveIntervalMinutes} minute(s); {timeline.EntriesWithTimestamps:N0} entries have parsed timestamps and {timeline.EntriesWithoutTimestamps:N0} do not.").AppendLine();
            output.AppendLine("| UTC start | Entries | Warnings | Errors |").AppendLine("|---|---:|---:|---:|");
            foreach (var bucket in timeline.Buckets.Where(bucket => bucket.TotalCount > 0).Take(200))
                output.AppendLine($"| {bucket.StartUtc:yyyy-MM-dd HH:mm} | {bucket.TotalCount:N0} | {bucket.WarningCount:N0} | {bucket.ErrorCount:N0} |");
            output.AppendLine();
        }
        if (options.IncludeSequenceFindings)
        {
            output.AppendLine("## Sequence findings").AppendLine();
            if (sequences.Count == 0) output.AppendLine("No supported short sequence or repeated-failure pattern was found.").AppendLine();
            foreach (var finding in sequences.Take(200))
                output.AppendLine($"### {Escape(finding.Headline)}").AppendLine($"- **Type:** {finding.Kind} · **Source lines:** {string.Join(", ", finding.SourceLines)}")
                    .AppendLine($"- {Escape(finding.Explanation)}").AppendLine($"- **Evidence:** {Escape(finding.Evidence)}").AppendLine();
        }
        if (options.IncludeNotableEntries)
        {
            output.AppendLine("## Notable entries").AppendLine();
            var notable = GetNotableEntries(document, analysis).Take(200).ToArray();
            foreach (var (entry, finding) in notable)
            {
                output.AppendLine($"### Line {entry.SourceLine} · {entry.Severity} · {finding.Category}").AppendLine($"**{Escape(finding.Headline)}** — {Escape(entry.Message)}")
                    .AppendLine($"Tags: {string.Join(", ", finding.Tags.Select(Escape))} · Match strength: {finding.MatchStrength}");
                var keyDetails = KeyDetails(entry);
                if (keyDetails.Count > 0) output.AppendLine($"**Key details:** {string.Join(" · ", keyDetails.Select(pair => $"{Escape(pair.Key)}: {Escape(pair.Value)}"))}");
                output.AppendLine($"**Interpretation:** {Escape(entry.InterpretationBasis)}");
                foreach (var evidence in finding.Evidence) output.AppendLine($"- Evidence ({Escape(evidence.Field)}): {Escape(evidence.Value)}");
                if (options.IncludeRecommendations) foreach (var recommendation in finding.Recommendations) output.AppendLine($"- Suggested check: {Escape(recommendation)}");
                output.AppendLine();
            }
            if (GetNotableEntries(document, analysis).Skip(notable.Length).Any()) output.AppendLine("_Additional notable entries are omitted from this compact Markdown report._").AppendLine();
        }
        if (options.IncludeParserNotes && document.Warnings.Count > 0)
        {
            output.AppendLine("## Parser notes").AppendLine();
            foreach (var warning in document.Warnings.Take(100)) output.AppendLine($"- {Escape(warning)}");
            output.AppendLine();
        }
        output.AppendLine("## Limitations").AppendLine().AppendLine("Parsing and analysis are best-effort. Verify findings against the original log and surrounding records.");
        return output.ToString();
    }

    public string ExportJson(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences, LogTimelineReport? timeline = null, LogSequenceAnalysisOptions? sequenceOptions = null, LogReportOptions? options = null)
    {
        options ??= new LogReportOptions();
        sequenceOptions ??= new LogSequenceAnalysisOptions();
        var notable = (options.IncludeNotableEntries ? GetNotableEntries(document, analysis) : []).Take(MaximumFindingsInReport)
            .Select(pair => new ExportedEntry(pair.Entry.Index, pair.Entry.SourceLine, pair.Entry.Timestamp, pair.Entry.Severity, pair.Entry.Source,
                pair.Entry.Message, pair.Entry.SourceLineEnd, KeyDetails(pair.Entry), pair.Entry.InterpretationBasis, pair.Finding.Category, pair.Finding.Headline, pair.Finding.MatchStrength, pair.Finding.Tags, pair.Finding.Evidence,
                options.IncludeRecommendations ? pair.Finding.Recommendations : Array.Empty<string>())).ToArray();
        var payload = new
        {
            schemaVersion = 1,
            generatedAt = DateTimeOffset.UtcNow,
            source = new { document.FileName, fileType = document.FileTypeLabel, document.Format, document.ContentKind, document.DetectedEncoding, document.ByteLength, parserProfile = document.Entries.FirstOrDefault()?.Fields.GetValueOrDefault("ParserProfile") },
            options,
            sequenceAnalysisOptions = sequenceOptions,
            summary = options.IncludeSummary || options.IncludeCategorySummary ? new
            {
                entryCount = options.IncludeSummary ? analysis.EntryCount : (int?)null,
                classifiedCount = options.IncludeSummary ? analysis.ClassifiedCount : (int?)null,
                errorCount = options.IncludeSummary ? analysis.ErrorCount : (int?)null,
                warningCount = options.IncludeSummary ? analysis.WarningCount : (int?)null,
                categoryCounts = options.IncludeCategorySummary ? analysis.CategoryCounts : null
            } : null,
            interpretationNote = "Rule-based labels and sequences are review aids; they do not establish root cause.",
            parserNotes = options.IncludeParserNotes ? document.Warnings : [],
            sequenceFindings = options.IncludeSequenceFindings ? sequences.Take(500) : [],
            timeline = options.IncludeTimeline ? timeline : null,
            entriesIncluded = notable.Length,
            entriesOmitted = Math.Max(0, document.Entries.Count - notable.Length),
            notableEntries = notable
        };
        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    private static IEnumerable<(ParsedLogEntry Entry, LogEntryAnalysis Finding)> GetNotableEntries(LogDocument document, LogAnalysisReport analysis) =>
        document.Entries.Select(entry => (Entry: entry, Finding: analysis.Entries[entry.Index]))
            .Where(pair => pair.Entry.Severity is LogEntrySeverity.Warning or LogEntrySeverity.Error or LogEntrySeverity.Critical ||
                pair.Finding.MatchStrength is RuleMatchStrength.Strong or RuleMatchStrength.Moderate ||
                pair.Finding.Category is not (LogScenarioCategory.Unclassified or LogScenarioCategory.Operational))
            .OrderByDescending(pair => pair.Entry.Severity is LogEntrySeverity.Critical or LogEntrySeverity.Error ? 2 : pair.Entry.Severity == LogEntrySeverity.Warning ? 1 : 0)
            .ThenBy(pair => pair.Entry.SourceLine);

    private static IReadOnlyDictionary<string, string> KeyDetails(ParsedLogEntry entry)
    {
        var preferred = new[] { "ErrorCode", "Code", "EventId", "EventID", "StatusCode", "ProcessId", "Process", "ThreadId", "RequestId", "CorrelationId", "TransactionId", "Path", "Method", "ClientIp", "Host", "Provider", "ServiceName", "Computer" };
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (entry.Timestamp is { } timestamp) details["TimestampUtc"] = timestamp.ToUniversalTime().ToString("O");
        if (!string.IsNullOrWhiteSpace(entry.Source)) details["Source"] = entry.Source;
        foreach (var key in preferred)
            if (entry.Fields.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)) details.TryAdd(key, value.Length > 500 ? value[..500] : value);
        return details;
    }

    private static string Escape(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
        .Replace("|", "\\|").Replace("`", "\\`").Replace("\r", " ").Replace("\n", " ");
    private sealed record ExportedEntry(int Index, int SourceLine, DateTimeOffset? Timestamp, LogEntrySeverity Severity, string? Source,
        string Message, int SourceLineEnd, IReadOnlyDictionary<string, string> KeyDetails, string InterpretationBasis, LogScenarioCategory Category, string Headline, RuleMatchStrength MatchStrength, IReadOnlyList<string> Tags,
        IReadOnlyList<LogEvidence> Evidence, IReadOnlyList<string> Recommendations);
}
