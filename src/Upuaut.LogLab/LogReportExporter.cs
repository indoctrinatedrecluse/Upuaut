using System.Text;
using System.Text.Json;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public sealed class LogReportExporter : ILogReportExporter
{
    private const int MaximumFindingsInReport = 10_000;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string ExportMarkdown(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences)
    {
        var output = new StringBuilder();
        output.AppendLine("# Upuaut Log Lab Investigation Report").AppendLine();
        output.AppendLine($"- **Source:** {Escape(document.FileName)}").AppendLine($"- **Generated:** {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}")
            .AppendLine($"- **Format:** {document.Format} · **Encoding:** {Escape(document.DetectedEncoding)} · **Size:** {document.ByteLength:N0} bytes")
            .AppendLine($"- **Entries:** {analysis.EntryCount:N0} · **Errors:** {analysis.ErrorCount:N0} · **Warnings:** {analysis.WarningCount:N0}")
            .AppendLine("- **Interpretation:** scenario labels and sequence groupings are rule-based review aids, not root-cause conclusions.").AppendLine();
        output.AppendLine("## Scenario summary").AppendLine().AppendLine("| Category | Entries |").AppendLine("|---|---:|");
        foreach (var category in analysis.CategoryCounts) output.AppendLine($"| {category.Category} | {category.Count:N0} |");
        output.AppendLine().AppendLine("## Sequence findings").AppendLine();
        if (sequences.Count == 0) output.AppendLine("No supported short sequence or repeated-failure pattern was found.").AppendLine();
        foreach (var finding in sequences.Take(200))
            output.AppendLine($"### {Escape(finding.Headline)}").AppendLine($"- **Type:** {finding.Kind} · **Source lines:** {string.Join(", ", finding.SourceLines)}")
                .AppendLine($"- {Escape(finding.Explanation)}").AppendLine($"- **Evidence:** {Escape(finding.Evidence)}").AppendLine();
        output.AppendLine("## Notable entries").AppendLine();
        var notable = GetNotableEntries(document, analysis).Take(200).ToArray();
        foreach (var (entry, finding) in notable)
            output.AppendLine($"### Line {entry.SourceLine} · {entry.Severity} · {finding.Category}").AppendLine($"**{Escape(finding.Headline)}** — {Escape(entry.Message)}")
                .AppendLine($"Tags: {string.Join(", ", finding.Tags.Select(Escape))} · Match strength: {finding.MatchStrength}").AppendLine();
        if (GetNotableEntries(document, analysis).Skip(notable.Length).Any()) output.AppendLine("_Additional notable entries are omitted from this compact Markdown report._").AppendLine();
        output.AppendLine("## Limitations").AppendLine().AppendLine("Parsing and analysis are best-effort. Verify findings against the original log and surrounding records.");
        return output.ToString();
    }

    public string ExportJson(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences)
    {
        var notable = GetNotableEntries(document, analysis).Take(MaximumFindingsInReport)
            .Select(pair => new ExportedEntry(pair.Entry.Index, pair.Entry.SourceLine, pair.Entry.Timestamp, pair.Entry.Severity, pair.Entry.Source,
                pair.Entry.Message, pair.Finding.Category, pair.Finding.Headline, pair.Finding.MatchStrength, pair.Finding.Tags, pair.Finding.Evidence, pair.Finding.Recommendations)).ToArray();
        var payload = new
        {
            schemaVersion = 1,
            generatedAt = DateTimeOffset.UtcNow,
            source = new { document.FileName, document.Format, document.DetectedEncoding, document.ByteLength, parserProfile = document.Entries.FirstOrDefault()?.Fields.GetValueOrDefault("ParserProfile") },
            summary = new { analysis.EntryCount, analysis.ClassifiedCount, analysis.ErrorCount, analysis.WarningCount, analysis.CategoryCounts },
            interpretationNote = "Rule-based labels and sequences are review aids; they do not establish root cause.",
            parserNotes = document.Warnings,
            sequenceFindings = sequences.Take(500),
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

    private static string Escape(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
        .Replace("|", "\\|").Replace("`", "\\`").Replace("\r", " ").Replace("\n", " ");
    private sealed record ExportedEntry(int Index, int SourceLine, DateTimeOffset? Timestamp, LogEntrySeverity Severity, string? Source,
        string Message, LogScenarioCategory Category, string Headline, RuleMatchStrength MatchStrength, IReadOnlyList<string> Tags,
        IReadOnlyList<LogEvidence> Evidence, IReadOnlyList<string> Recommendations);
}
