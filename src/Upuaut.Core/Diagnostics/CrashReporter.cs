using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Upuaut.Core.Diagnostics;

public record CrashReport(
    string ReportId,
    DateTime TimestampUtc,
    string AppVersion,
    string FrameworkDescription,
    string OsDescription,
    string OsArchitecture,
    string ProcessArchitecture,
    bool IsElevated,
    long WorkingSetBytes,
    long PeakWorkingSetBytes,
    long GcTotalMemoryBytes,
    int ThreadCount,
    string ExceptionType,
    string ExceptionMessage,
    string HexHResult,
    string? StackTrace,
    IReadOnlyList<CrashExceptionDetail> InnerExceptions,
    IReadOnlyList<InternalLogEntry> Breadcrumbs);

public record CrashExceptionDetail(
    string Type,
    string Message,
    string HexHResult,
    string? StackTrace);

/// <summary>
/// Robust crash dump generator. Creates comprehensive forensic snapshots of application state
/// including memory telemetry, OS environment, nested exceptions, and recent log breadcrumbs.
/// </summary>
public static class CrashReporter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string GenerateCrashDump(Exception ex, string context = "Unhandled Exception")
    {
        var timestamp = DateTime.UtcNow;
        var reportId = $"CRASH-{timestamp:yyyyMMdd-HHmmss}-{Environment.ProcessId}";

        AppLogger.Fatal("CrashReporter", $"Generating forensic crash snapshot: {reportId} (Context: {context})", ex);

        // 1. Gather Telemetry
        bool isElevated = false;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                isElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        catch
        {
            // Ignore if security principal check fails
        }

        var proc = Process.GetCurrentProcess();
        proc.Refresh();

        var innerExceptions = new List<CrashExceptionDetail>();
        var current = ex.InnerException;
        while (current != null)
        {
            innerExceptions.Add(new CrashExceptionDetail(
                Type: current.GetType().FullName ?? current.GetType().Name,
                Message: current.Message,
                HexHResult: $"0x{current.HResult:X8}",
                StackTrace: current.StackTrace));
            current = current.InnerException;
        }

        var report = new CrashReport(
            ReportId: reportId,
            TimestampUtc: timestamp,
            AppVersion: Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "0.1.0",
            FrameworkDescription: RuntimeInformation.FrameworkDescription,
            OsDescription: RuntimeInformation.OSDescription,
            OsArchitecture: RuntimeInformation.OSArchitecture.ToString(),
            ProcessArchitecture: RuntimeInformation.ProcessArchitecture.ToString(),
            IsElevated: isElevated,
            WorkingSetBytes: proc.WorkingSet64,
            PeakWorkingSetBytes: proc.PeakWorkingSet64,
            GcTotalMemoryBytes: GC.GetTotalMemory(false),
            ThreadCount: proc.Threads.Count,
            ExceptionType: ex.GetType().FullName ?? ex.GetType().Name,
            ExceptionMessage: ex.Message,
            HexHResult: $"0x{ex.HResult:X8}",
            StackTrace: ex.StackTrace,
            InnerExceptions: innerExceptions,
            Breadcrumbs: AppLogger.GetRecentBreadcrumbs().TakeLast(50).ToList());

        // 2. Persist JSON Dump
        var jsonFileName = $"crash_{timestamp:yyyyMMdd_HHmmss}_{Environment.ProcessId}.json";
        var jsonFilePath = Path.Combine(AppLogger.CrashDirectory, jsonFileName);
        try
        {
            var json = JsonSerializer.Serialize(report, JsonOptions);
            File.WriteAllText(jsonFilePath, json);
        }
        catch
        {
            // Ignore serialization errors
        }

        // 3. Persist Markdown Forensic Report
        var mdFileName = $"crash_{timestamp:yyyyMMdd_HHmmss}_{Environment.ProcessId}.md";
        var mdFilePath = Path.Combine(AppLogger.CrashDirectory, mdFileName);
        try
        {
            var md = BuildMarkdownSummary(report, context);
            File.WriteAllText(mdFilePath, md);
        }
        catch
        {
            // Ignore write errors
        }

        AppLogger.Info("CrashReporter", $"Crash snapshot successfully written to {mdFilePath}");
        return mdFilePath;
    }

    public static string BuildMarkdownSummary(CrashReport report, string context)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# 🐺 Upuaut Fatal Exception Report");
        sb.AppendLine($"**Report ID:** `{report.ReportId}`  ");
        sb.AppendLine($"**Context:** {context}  ");
        sb.AppendLine($"**Timestamp:** {report.TimestampUtc:yyyy-MM-dd HH:mm:ss.fff} UTC  ");
        sb.AppendLine();

        sb.AppendLine("## 🚨 Exception Details");
        sb.AppendLine($"- **Type:** `{report.ExceptionType}`");
        sb.AppendLine($"- **HRESULT:** `{report.HexHResult}`");
        sb.AppendLine($"- **Message:** {report.ExceptionMessage}");
        sb.AppendLine();

        sb.AppendLine("### Stack Trace");
        sb.AppendLine("```text");
        sb.AppendLine(report.StackTrace ?? "(No stack trace available)");
        sb.AppendLine("```");
        sb.AppendLine();

        if (report.InnerExceptions.Count > 0)
        {
            sb.AppendLine("## ⛓️ Inner Exception Chain");
            for (int i = 0; i < report.InnerExceptions.Count; i++)
            {
                var inner = report.InnerExceptions[i];
                sb.AppendLine($"### Inner Exception #{i + 1}: `{inner.Type}`");
                sb.AppendLine($"- **HRESULT:** `{inner.HexHResult}`");
                sb.AppendLine($"- **Message:** {inner.Message}");
                sb.AppendLine("```text");
                sb.AppendLine(inner.StackTrace ?? "(No inner stack trace)");
                sb.AppendLine("```");
                sb.AppendLine();
            }
        }

        sb.AppendLine("## 🖥️ System & Runtime Environment");
        sb.AppendLine($"- **Application Version:** `{report.AppVersion}`");
        sb.AppendLine($"- **Runtime:** `{report.FrameworkDescription}`");
        sb.AppendLine($"- **OS:** `{report.OsDescription}` ({report.OsArchitecture})");
        sb.AppendLine($"- **Process Arch:** `{report.ProcessArchitecture}`");
        sb.AppendLine($"- **Privilege:** {(report.IsElevated ? "**Administrator (Elevated)**" : "Standard User")}");
        sb.AppendLine($"- **Memory (Working Set):** {report.WorkingSetBytes / (1024 * 1024):N1} MB (Peak: {report.PeakWorkingSetBytes / (1024 * 1024):N1} MB)");
        sb.AppendLine($"- **Active Threads:** {report.ThreadCount}");
        sb.AppendLine();

        if (report.Breadcrumbs.Count > 0)
        {
            sb.AppendLine("## 📜 Diagnostic Breadcrumbs (Pre-Crash Events)");
            sb.AppendLine("| Time (UTC) | Level | Category | Message |");
            sb.AppendLine("| :--- | :--- | :--- | :--- |");
            foreach (var b in report.Breadcrumbs)
            {
                var cleanMsg = b.Message.Replace("|", "\\|").Replace("\n", " ");
                sb.AppendLine($"| `{b.Timestamp:HH:mm:ss.fff}` | `{b.Level}` | `{b.Category}` | {cleanMsg} |");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }
}
