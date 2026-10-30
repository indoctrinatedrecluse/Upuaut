using System.Text.RegularExpressions;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>Finds repeated signatures and short warning/error/recovery sequences without inferring causation.</summary>
public sealed class LogSequenceAnalysisEngine : ILogSequenceAnalysisEngine
{
    private const int MaximumFindings = 500;
    private static readonly Regex GuidPattern = new(@"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex NumberPattern = new(@"\b\d+\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public IReadOnlyList<LogSequenceFinding> Analyze(LogDocument document, LogSequenceAnalysisOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(document);
        options ??= new LogSequenceAnalysisOptions();
        var window = TimeSpan.FromMinutes(Math.Clamp(options.WindowMinutes, 1, 1440));
        var findings = new List<LogSequenceFinding>();
        var ordered = document.Entries.OrderBy(entry => entry.SourceLine).ToArray();

        foreach (var group in document.Entries.Where(IsFailure)
                     .Select(entry => (Entry: entry, Signature: Normalize(entry.Source + " " + entry.Message)))
                     .GroupBy(item => item.Signature, StringComparer.OrdinalIgnoreCase)
                     .Where(group => group.Count() >= 2).OrderByDescending(group => group.Count()).Take(100))
        {
            var entries = group.Select(item => item.Entry).OrderBy(entry => entry.SourceLine).Take(30).ToArray();
            findings.Add(new LogSequenceFinding(LogSequenceKind.RepeatedFailure,
                $"Repeated failure signature ({group.Count():N0} entries)",
                "Multiple error-severity entries share the same message after common changing IDs and numbers are normalized. This groups similar records; it does not establish a shared cause.",
                entries.Select(entry => entry.Index).ToArray(), entries.Select(entry => entry.SourceLine).ToArray(),
                entries.Select(entry => entry.Timestamp).FirstOrDefault(time => time.HasValue), entries.Select(entry => entry.Timestamp).LastOrDefault(time => time.HasValue), Clip(group.Key)));
            if (findings.Count >= MaximumFindings) return findings;
        }

        for (var i = 0; i + 1 < ordered.Length && findings.Count < MaximumFindings; i++)
        {
            var first = ordered[i];
            if (options.SameComponentOnly && string.IsNullOrWhiteSpace(first.Source)) continue;
            var candidates = ordered.Skip(i + 1).Take(8)
                .Where(candidate => WithinWindow(first, candidate, window))
                .Where(candidate => !options.SameComponentOnly || string.Equals(first.Source, candidate.Source, StringComparison.OrdinalIgnoreCase)).ToArray();
            var next = first.Severity == LogEntrySeverity.Warning
                ? candidates.FirstOrDefault(IsFailure)
                : IsFailure(first) ? candidates.FirstOrDefault(candidate => candidate.Severity == LogEntrySeverity.Success) : null;
            if (next is null) continue;
            if (first.Severity == LogEntrySeverity.Warning)
                findings.Add(Pair(LogSequenceKind.WarningEscalated, "Warning followed by an error", "A warning is followed by an error within the short review window. The ordering is useful for investigation but does not prove the warning caused the error.", first, next));
            else
                findings.Add(Pair(LogSequenceKind.ErrorFollowedByRecovery, "Error followed by a success signal", "A success-level entry follows an error within the short review window. Confirm that it refers to the same operation before treating it as recovery.", first, next));
        }
        return findings;
    }

    private static LogSequenceFinding Pair(LogSequenceKind kind, string headline, string explanation, ParsedLogEntry first, ParsedLogEntry next) =>
        new(kind, headline, explanation, [first.Index, next.Index], [first.SourceLine, next.SourceLine], first.Timestamp, next.Timestamp,
            $"Line {first.SourceLine}: {Clip(first.Message)} → Line {next.SourceLine}: {Clip(next.Message)}");

    private static bool WithinWindow(ParsedLogEntry first, ParsedLogEntry next, TimeSpan window)
    {
        if (first.Timestamp is { } start && next.Timestamp is { } end) return end >= start && end - start <= window;
        return next.SourceLine > first.SourceLine && next.SourceLine - first.SourceLine <= 40;
    }

    private static bool IsFailure(ParsedLogEntry entry) => entry.Severity is LogEntrySeverity.Error or LogEntrySeverity.Critical;
    private static string Normalize(string value) => NumberPattern.Replace(GuidPattern.Replace(value, "{id}"), "{n}").Trim().ToLowerInvariant();
    private static string Clip(string value) => value.Length <= 400 ? value : value[..397] + "...";
}
