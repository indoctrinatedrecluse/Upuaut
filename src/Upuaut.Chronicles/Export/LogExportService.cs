using System.Text;
using System.Text.Json;
using Upuaut.Core.Models;

namespace Upuaut.Chronicles.Export;

public class LogExportService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true
    };

    public string Export(IEnumerable<LogRecord> logs, LogExportFormat format)
    {
        return format switch
        {
            LogExportFormat.Markdown => GenerateMarkdownReport(logs),
            LogExportFormat.Json => GenerateJson(logs),
            LogExportFormat.Csv => GenerateCsv(logs),
            _ => GenerateMarkdownReport(logs)
        };
    }

    private static string GenerateJson(IEnumerable<LogRecord> logs)
    {
        return JsonSerializer.Serialize(logs, JsonOpts);
    }

    private static string GenerateCsv(IEnumerable<LogRecord> logs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Timestamp,Level,EventID,Provider,Channel,ProcessID,TriageRating,Summary,Message");

        foreach (var log in logs)
        {
            var summary = EscapeCsv(log.Explanation?.Summary ?? string.Empty);
            var msg = EscapeCsv(log.Message);
            var provider = EscapeCsv(log.ProviderName);
            var triage = log.Explanation?.TriageRating.ToString() ?? "Standard";

            sb.AppendLine($"{log.Timestamp:O},{log.Level},{log.EventId},{provider},{log.Channel},{log.ProcessId},{triage},{summary},{msg}");
        }

        return sb.ToString();
    }

    private static string GenerateMarkdownReport(IEnumerable<LogRecord> logs)
    {
        var logList = logs.ToList();
        var sb = new StringBuilder();

        sb.AppendLine("# 🐺 Upuaut Diagnostic Triage Report");
        sb.AppendLine($"> *Generated on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC by Upuaut — Opener of the Ways*");
        sb.AppendLine();

        // 1. Executive Summary
        var criticalCount = logList.Count(l => l.Level == LogSeverityLevel.Critical);
        var errorCount = logList.Count(l => l.Level == LogSeverityLevel.Error);
        var warningCount = logList.Count(l => l.Level == LogSeverityLevel.Warning);
        var noiseCount = logList.Count(l => l.Explanation?.TriageRating == TriageSeverity.BenignNoise);

        sb.AppendLine("## 📊 Executive Summary");
        sb.AppendLine("| Metric | Count | Note |");
        sb.AppendLine("| :--- | :--- | :--- |");
        sb.AppendLine($"| **Total Events** | {logList.Count} | Analyzed records |");
        sb.AppendLine($"| **Critical Issues** | {criticalCount} | Kernel / Power / BSOD |");
        sb.AppendLine($"| **Errors** | {errorCount} | App crashes, service failures |");
        sb.AppendLine($"| **Warnings** | {warningCount} | Timeouts & notices |");
        sb.AppendLine($"| **Benign Noise** | {noiseCount} | Suppressed safe telemetry (DCOM, etc.) |");
        sb.AppendLine();

        // 2. High-Priority Actionable Events
        var actionable = logList
            .Where(l => l.Explanation?.TriageRating is TriageSeverity.Critical or TriageSeverity.High)
            .Take(15)
            .ToList();

        if (actionable.Count > 0)
        {
            sb.AppendLine("## 🚨 Critical & High Severity Findings (The Oracle Triage)");
            sb.AppendLine();

            foreach (var item in actionable)
            {
                sb.AppendLine($"### ✦ [{item.Level}] Event {item.EventId} — {item.ProviderName}");
                sb.AppendLine($"- **Timestamp:** `{item.Timestamp:yyyy-MM-dd HH:mm:ss.fff}`");
                sb.AppendLine($"- **Triage Rating:** `{item.Explanation?.TriageRating}`");
                sb.AppendLine($"- **Plain English Summary:** {item.Explanation?.Summary}");

                if (!string.IsNullOrEmpty(item.Explanation?.DecodedStatusCode))
                {
                    sb.AppendLine($"- **Decoded Status Code:** `{item.Explanation.DecodedStatusCode}` ({item.Explanation.StatusMeaning})");
                }

                if (item.Explanation?.ProbableCauses.Count > 0)
                {
                    sb.AppendLine("- **Probable Causes:**");
                    foreach (var cause in item.Explanation.ProbableCauses)
                    {
                        sb.AppendLine($"  - {cause}");
                    }
                }

                if (item.Explanation?.RecommendedActions.Count > 0)
                {
                    sb.AppendLine("- **Recommended Remediation:**");
                    foreach (var action in item.Explanation.RecommendedActions)
                    {
                        sb.AppendLine($"  - [ ] {action}");
                    }
                }

                sb.AppendLine();
                sb.AppendLine("```text");
                sb.AppendLine(item.Message.Length > 400 ? item.Message[..400] + "..." : item.Message);
                sb.AppendLine("```");
                sb.AppendLine();
            }
        }

        // 3. Complete Event Log Listing
        sb.AppendLine("## 📜 Log Records Inventory");
        sb.AppendLine("| Timestamp (UTC) | Severity | ID | Provider | Plain English Summary |");
        sb.AppendLine("| :--- | :--- | :--- | :--- | :--- |");

        foreach (var l in logList.Take(100))
        {
            var summary = l.Explanation?.Summary ?? l.Message;
            if (summary.Length > 80) summary = summary[..80] + "...";
            summary = summary.Replace("|", "\\|");

            sb.AppendLine($"| `{l.Timestamp:HH:mm:ss.fff}` | {l.Level} | {l.EventId} | `{l.ProviderName}` | {summary} |");
        }

        if (logList.Count > 100)
        {
            sb.AppendLine($"\n*... and {logList.Count - 100} additional events.*");
        }

        return sb.ToString();
    }

    private static string EscapeCsv(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }
        return value;
    }
}
