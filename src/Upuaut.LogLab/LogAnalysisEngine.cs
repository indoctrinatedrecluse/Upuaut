using System.Text;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>Deterministic, evidence-grounded scenario labeling for parsed log entries.</summary>
public sealed class LogAnalysisEngine : ILogAnalysisEngine
{
    private sealed record Rule(
        LogScenarioCategory Category,
        string Headline,
        string Explanation,
        string[] Signals,
        string[] Tags,
        string[] Recommendations);

    private static readonly Rule[] Rules =
    [
        new(LogScenarioCategory.Crash, "Crash or unhandled-exception signal", "Crash-related language was found in this entry. It identifies a crash signal in the log, not the underlying cause.",
            ["unhandled exception", "segmentation fault", "application crash", "process crashed", "stack trace", "traceback", "core dumped", "fatal exception", "crash"],
            ["process", "exception"], ["Review the surrounding entries for the first failure before this message.", "Inspect any exception type, module, process, or dump reference recorded in the source."]),
        new(LogScenarioCategory.Installation, "Installation or setup activity", "Installation-related terms were found. The entry may describe setup progress, completion, or failure; use its status and nearby entries to establish the outcome.",
            ["installation", "install", "installer", "setup", "msi", "package install", "uninstall"],
            ["setup", "package"], ["Check the installer result code and the first preceding error.", "Compare this step with later rollback, completion, or reboot entries."]),
        new(LogScenarioCategory.Update, "Software update activity", "Update or patch language was found in the entry. The text indicates update activity, not whether the update caused a later issue.",
            ["update", "upgrade", "patch", "rollback", "hotfix"],
            ["update", "deployment"], ["Check the package version and update result recorded nearby.", "Look for rollback, restart-required, or compatibility messages in adjacent entries."]),
        new(LogScenarioCategory.Authentication, "Authentication or sign-in event", "Authentication-related terms were found. Verify the identity, authentication method, and result in the original record.",
            ["authentication failed", "authentication failure", "failed to authenticate", "failed password", "account locked", "login failed", "logon failure", "invalid password", "invalid credentials", "token expired", "sign-in failed"],
            ["identity", "authentication"], ["Check the account, authentication method, and exact result code.", "Review nearby lockout, token-renewal, or identity-provider events."]),
        new(LogScenarioCategory.Security, "Security or access-control event", "Security or access-control language was found. This label does not establish whether the activity was malicious.",
            ["access denied", "permission denied", "unauthorized", "blocked by policy", "security alert", "intrusion", "certificate validation failed", "firewall blocked"],
            ["access-control", "security"], ["Verify the actor, target resource, and policy or permission named in the source.", "Correlate with adjacent audit events before treating this as suspicious activity."]),
        new(LogScenarioCategory.Network, "Network or name-resolution event", "Network-related terms were found. The record points to a connectivity or protocol event but does not identify where the fault lies.",
            ["connection timed out", "request timed out", "upstream connection", "upstream", "connection refused", "network unreachable", "host not found", "name resolution", "dns", "socket error", "handshake failed", "connection reset", "http 503", "http 502", "http 504", "http 5", "httpstatus", "http status", "endpoint"],
            ["connectivity", "network"], ["Check the remote endpoint, port, and timestamp captured in the entry.", "Compare with DNS, firewall, and service-availability records for the same interval."]),
        new(LogScenarioCategory.Storage, "Storage or file-system event", "Storage-related terms were found. Confirm the affected volume or path and the exact operation in the source.",
            ["disk full", "no space left", "i/o error", "read-only file system", "write failed", "disk error", "volume", "filesystem", "file system"],
            ["storage", "filesystem"], ["Identify the affected volume or path and check available space and health records.", "Review nearby read, write, retry, and device-reset messages."]),
        new(LogScenarioCategory.Service, "Service or background-process event", "Service lifecycle language was found. Check the service name and result before inferring impact.",
            ["failed to start service", "service failed", "service stopped", "service started", "service exited", "service recovered", "service restarted", "automatic restart", "daemon", "unit entered failed", "service restart"],
            ["service", "lifecycle"], ["Check the named service, its exit code, and its dependency state.", "Inspect entries immediately before the stop or restart for a triggering error."]),
        new(LogScenarioCategory.Performance, "Performance or resource-pressure event", "Performance or resource-pressure language was found. The entry alone does not show whether the condition was sustained or user-visible.",
            ["out of memory", "memory pressure", "resource exhausted", "high latency", "slow response", "deadlock detected", "deadlock victim", "deadlock", "cpu usage", "timed out", "timeout"],
            ["performance", "resource"], ["Check duration, affected component, and whether the condition repeats.", "Compare resource metrics with nearby workload and service events."]),
        new(LogScenarioCategory.Maintenance, "Maintenance or health-check activity", "Maintenance-related terms were found. Confirm whether the task completed and whether it reported affected items.",
            ["backup", "restore", "cleanup", "maintenance", "health check", "scheduled task", "scan completed", "integrity check"],
            ["maintenance", "scheduled-work"], ["Review the task result and any skipped or failed items.", "Compare the recorded task time with the system or application changes under investigation."]),
        new(LogScenarioCategory.Success, "Successful operation signal", "Completion or health language was found. Treat this as a reported success for this step only.",
            ["completed successfully", "successfully completed", "operation completed", "started successfully", "healthy", "passed", "succeeded"],
            ["success", "completion"], ["Check that a later entry confirms the full workflow completed.", "If investigating a failure, use the timestamp and component to compare this step with the first error."])
    ];

    public LogAnalysisReport Analyze(LogDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var analyses = new Dictionary<int, LogEntryAnalysis>(document.Entries.Count);
        var counts = new Dictionary<LogScenarioCategory, int>();
        var errors = 0;
        var warnings = 0;

        foreach (var entry in document.Entries)
        {
            var analysis = document.ContentKind == LogContentKind.BinaryLike
                ? new LogEntryAnalysis(entry.Index, LogScenarioCategory.Unclassified, "Binary-like data preview", "Scenario classification was skipped because this file is predominantly non-text or encrypted. Use the decoded raw preview for manual inspection.", RuleMatchStrength.NoRuleMatched, ["binary-like"], [], [])
                : Classify(entry);
            analyses[entry.Index] = analysis;
            counts[analysis.Category] = counts.GetValueOrDefault(analysis.Category) + 1;
            if (document.ContentKind != LogContentKind.BinaryLike)
            {
                if (entry.Severity is LogEntrySeverity.Error or LogEntrySeverity.Critical) errors++;
                if (entry.Severity == LogEntrySeverity.Warning) warnings++;
            }
        }

        var classified = analyses.Values.Count(result => result.Category != LogScenarioCategory.Unclassified);
        var categoryCounts = counts.OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key)
            .Select(pair => new LogCategoryCount(pair.Key, pair.Value)).ToArray();
        return new LogAnalysisReport(document.Entries.Count, classified, errors, warnings, categoryCounts, analyses);
    }

    private static LogEntryAnalysis Classify(ParsedLogEntry entry)
    {
        var text = BuildSearchText(entry);
        Rule? bestRule = null;
        string[] bestMatches = [];
        var bestScore = 0;
        foreach (var rule in Rules)
        {
            var found = rule.Signals.Where(signal => text.Contains(signal, StringComparison.OrdinalIgnoreCase)).ToArray();
            var matches = found.Where(signal => !found.Any(other => other.Length > signal.Length && other.Contains(signal, StringComparison.OrdinalIgnoreCase))).ToArray();
            var score = matches.Sum(signal => Math.Min(signal.Length, 24)) + matches.Length * 16;
            if (score > bestScore) { bestRule = rule; bestMatches = matches; bestScore = score; }
        }

        if (bestRule is null)
        {
            var category = entry.Severity switch
            {
                LogEntrySeverity.Critical => LogScenarioCategory.Failure,
                LogEntrySeverity.Error => LogScenarioCategory.Failure,
                LogEntrySeverity.Warning => LogScenarioCategory.Warning,
                LogEntrySeverity.Success => LogScenarioCategory.Success,
                LogEntrySeverity.Trace or LogEntrySeverity.Debug or LogEntrySeverity.Information => LogScenarioCategory.Operational,
                _ => LogScenarioCategory.Unclassified
            };
            var headline = category switch
            {
                LogScenarioCategory.Failure when entry.Severity == LogEntrySeverity.Critical => "Critical-severity entry (crash not confirmed)",
                LogScenarioCategory.Failure => "Error entry without a specific scenario match",
                LogScenarioCategory.Warning => "Warning entry without a specific scenario match",
                LogScenarioCategory.Success => "Success-level entry",
                LogScenarioCategory.Operational => "Operational log entry",
                _ => "No scenario pattern recognized"
            };
            var explanation = category == LogScenarioCategory.Unclassified
                ? "No supported scenario phrase or recognized severity was found. The entry remains available for manual review."
                : $"No specific scenario rule matched. The entry was grouped using its parsed severity ({entry.Severity}); review the raw source for context.";
            return new LogEntryAnalysis(entry.Index, category, headline, explanation, RuleMatchStrength.NoRuleMatched,
                BuildTags(category, entry.Severity, []), BuildEvidence(entry, []), GenericRecommendations(category));
        }

        var strength = bestMatches.Length >= 3 ? RuleMatchStrength.Strong : bestMatches.Length == 2 ? RuleMatchStrength.Moderate : RuleMatchStrength.Weak;
        var evidence = BuildEvidence(entry, bestMatches);
        var explanationText = evidence.Count == 0
            ? $"Matched signal(s): {string.Join(", ", bestMatches)}. {bestRule.Explanation}"
            : $"Matched signal(s): {string.Join(", ", bestMatches)}. {bestRule.Explanation}";
        return new LogEntryAnalysis(entry.Index, bestRule.Category, bestRule.Headline, explanationText, strength,
            BuildTags(bestRule.Category, entry.Severity, bestMatches), evidence, bestRule.Recommendations);
    }

    private static string BuildSearchText(ParsedLogEntry entry)
    {
        var builder = new StringBuilder(Math.Min(8192, entry.Message.Length + 256));
        AppendBounded(builder, entry.Message, 4096);
        AppendBounded(builder, entry.Source, 256);
        foreach (var (key, value) in entry.Fields.Take(32))
        {
            AppendBounded(builder, key, 96);
            AppendBounded(builder, value, 256);
            if (builder.Length >= 8192) break;
        }
        return builder.ToString();
    }

    private static void AppendBounded(StringBuilder builder, string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || builder.Length >= 8192) return;
        builder.Append(' ').Append(value.AsSpan(0, Math.Min(value.Length, maxLength)));
    }

    private static IReadOnlyList<LogEvidence> BuildEvidence(ParsedLogEntry entry, IReadOnlyList<string> signals)
    {
        var evidence = new List<LogEvidence>();
        foreach (var signal in signals.Take(4))
        {
            var field = entry.Fields.FirstOrDefault(pair => pair.Value.Contains(signal, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(field.Key)) evidence.Add(new LogEvidence(field.Key, Clip(field.Value)));
            else if (entry.Fields.FirstOrDefault(pair => pair.Key.Contains(signal, StringComparison.OrdinalIgnoreCase)) is { Key.Length: > 0 } namedField)
                evidence.Add(new LogEvidence(namedField.Key, Clip(namedField.Value)));
            else if (entry.Message.Contains(signal, StringComparison.OrdinalIgnoreCase)) evidence.Add(new LogEvidence("Message", Clip(entry.Message)));
            else if (entry.RawText.Contains(signal, StringComparison.OrdinalIgnoreCase))
            {
                var position = entry.RawText.IndexOf(signal, StringComparison.OrdinalIgnoreCase);
                var start = Math.Max(0, position - 90);
                var length = Math.Min(240, entry.RawText.Length - start);
                evidence.Add(new LogEvidence("Raw source", Clip(entry.RawText.Substring(start, length))));
            }
            else if (entry.Source?.Contains(signal, StringComparison.OrdinalIgnoreCase) == true) evidence.Add(new LogEvidence("Source", Clip(entry.Source)));
        }
        if (evidence.Count == 0 && !string.IsNullOrWhiteSpace(entry.Message)) evidence.Add(new LogEvidence("Message", Clip(entry.Message)));
        return evidence.DistinctBy(item => (item.Field, item.Value)).ToArray();
    }

    private static IReadOnlyList<string> BuildTags(LogScenarioCategory category, LogEntrySeverity severity, IEnumerable<string> signals)
    {
        var tags = new List<string> { category.ToString().ToLowerInvariant() };
        if (severity != LogEntrySeverity.Unknown) tags.Add(severity.ToString().ToLowerInvariant());
        tags.AddRange(signals.Take(3).Select(signal => signal.Replace(' ', '-')));
        return tags.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IReadOnlyList<string> GenericRecommendations(LogScenarioCategory category) => category switch
    {
        LogScenarioCategory.Failure => ["Inspect the first preceding warning or error and its component.", "Compare the timestamp and event identifier with related records."],
        LogScenarioCategory.Warning => ["Check whether a later entry reports recovery or escalation.", "Review the affected component and neighboring events for context."],
        LogScenarioCategory.Success => ["Confirm a later record reports completion of the full operation."],
        _ => ["Review the raw entry and surrounding lines for context.", "Search for related entries by component, timestamp, or identifier."]
    };

    private static string Clip(string value) => value.Length <= 280 ? value : value[..277] + "...";
}
