using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Upuaut.Core.Diagnostics;

public enum LogLevel
{
    Debug,
    Info,
    Warning,
    Error,
    Fatal
}

public record InternalLogEntry(
    DateTime Timestamp,
    LogLevel Level,
    string Category,
    string Message,
    string? ExceptionDetails = null,
    string? MemberName = null,
    string? FilePath = null,
    int LineNumber = 0,
    int ThreadId = 0);

/// <summary>
/// Thread-safe, high-performance diagnostic logger for Upuaut.
/// Manages rolling daily log files, structured JSONL telemetry, and an in-memory breadcrumb buffer.
/// </summary>
public static class AppLogger
{
    private static readonly object _syncRoot = new();
    private static readonly ConcurrentQueue<InternalLogEntry> _breadcrumbs = new();
    private const int MaxBreadcrumbs = 250;

    public static string LogDirectory { get; }
    public static string CrashDirectory { get; }
    public static string TodayLogFilePath => Path.Combine(LogDirectory, $"upuaut_{DateTime.UtcNow:yyyyMMdd}.log");
    public static string JsonLogFilePath => Path.Combine(LogDirectory, $"upuaut_telemetry_{DateTime.UtcNow:yyyyMMdd}.jsonl");

    public static event Action<InternalLogEntry>? OnLogEntry;

    static AppLogger()
    {
        try
        {
            var baseDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Upuaut");

            LogDirectory = Path.Combine(baseDataDir, "Logs");
            CrashDirectory = Path.Combine(baseDataDir, "Crashes");

            Directory.CreateDirectory(LogDirectory);
            Directory.CreateDirectory(CrashDirectory);
        }
        catch
        {
            // Fallback to application base directory if LocalAppData is inaccessible
            var fallback = AppDomain.CurrentDomain.BaseDirectory;
            LogDirectory = Path.Combine(fallback, "logs");
            CrashDirectory = Path.Combine(fallback, "crashes");
            Directory.CreateDirectory(LogDirectory);
            Directory.CreateDirectory(CrashDirectory);
        }

        Info("AppLogger", $"Diagnostic logging initialized under: {LogDirectory}");
    }

    public static IReadOnlyList<InternalLogEntry> GetRecentBreadcrumbs()
    {
        return _breadcrumbs.ToArray();
    }

    public static void Debug(string category, string message, [CallerMemberName] string member = "", [CallerFilePath] string file = "", [CallerLineNumber] int line = 0)
        => WriteEntry(LogLevel.Debug, category, message, null, member, file, line);

    public static void Info(string category, string message, [CallerMemberName] string member = "", [CallerFilePath] string file = "", [CallerLineNumber] int line = 0)
        => WriteEntry(LogLevel.Info, category, message, null, member, file, line);

    public static void Warning(string category, string message, Exception? ex = null, [CallerMemberName] string member = "", [CallerFilePath] string file = "", [CallerLineNumber] int line = 0)
        => WriteEntry(LogLevel.Warning, category, message, ex, member, file, line);

    public static void Error(string category, string message, Exception? ex = null, [CallerMemberName] string member = "", [CallerFilePath] string file = "", [CallerLineNumber] int line = 0)
        => WriteEntry(LogLevel.Error, category, message, ex, member, file, line);

    public static void Fatal(string category, string message, Exception? ex = null, [CallerMemberName] string member = "", [CallerFilePath] string file = "", [CallerLineNumber] int line = 0)
        => WriteEntry(LogLevel.Fatal, category, message, ex, member, file, line);

    private static void WriteEntry(
        LogLevel level,
        string category,
        string message,
        Exception? ex,
        string member,
        string file,
        int line)
    {
        var entry = new InternalLogEntry(
            Timestamp: DateTime.UtcNow,
            Level: level,
            Category: category,
            Message: message,
            ExceptionDetails: ex?.ToString(),
            MemberName: member,
            FilePath: string.IsNullOrEmpty(file) ? null : Path.GetFileName(file),
            LineNumber: line,
            ThreadId: Environment.CurrentManagedThreadId);

        // Maintain in-memory breadcrumbs
        _breadcrumbs.Enqueue(entry);
        while (_breadcrumbs.Count > MaxBreadcrumbs)
        {
            _breadcrumbs.TryDequeue(out _);
        }

        // Fire live listener
        try
        {
            OnLogEntry?.Invoke(entry);
        }
        catch
        {
            // Ignore subscriber errors
        }

        // Flush to persistent disk files
        WriteToDisk(entry);
    }

    private static void WriteToDisk(InternalLogEntry entry)
    {
        lock (_syncRoot)
        {
            try
            {
                // 1. Human-Readable Log Line
                var levelTag = entry.Level switch
                {
                    LogLevel.Debug => "[DEBUG]",
                    LogLevel.Info => "[INFO ]",
                    LogLevel.Warning => "[WARN ]",
                    LogLevel.Error => "[ERROR]",
                    LogLevel.Fatal => "[FATAL]",
                    _ => "[LOG  ]"
                };

                var caller = entry.FilePath != null ? $" ({entry.FilePath}:{entry.LineNumber} -> {entry.MemberName})" : "";
                var line = $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff}Z] {levelTag} [T{entry.ThreadId:D2}] [{entry.Category}] {entry.Message}{caller}\n";

                if (!string.IsNullOrEmpty(entry.ExceptionDetails))
                {
                    line += $"    EXCEPTION: {entry.ExceptionDetails}\n";
                }

                File.AppendAllText(TodayLogFilePath, line);

                // 2. Structured JSONL Record
                var json = JsonSerializer.Serialize(entry);
                File.AppendAllText(JsonLogFilePath, json + "\n");
            }
            catch
            {
                // Avoid recursive crash from logging failure
            }
        }
    }

    /// <summary>
    /// Opens the diagnostic logs directory in Windows Explorer.
    /// </summary>
    public static void OpenLogFolder()
    {
        try
        {
            if (Directory.Exists(LogDirectory))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{LogDirectory}\"",
                    UseShellExecute = true
                });
            }
        }
        catch (Exception ex)
        {
            Error("AppLogger", "Failed to open log directory in Explorer", ex);
        }
    }

    /// <summary>
    /// Opens the crash reports directory in Windows Explorer.
    /// </summary>
    public static void OpenCrashFolder()
    {
        try
        {
            if (Directory.Exists(CrashDirectory))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{CrashDirectory}\"",
                    UseShellExecute = true
                });
            }
        }
        catch (Exception ex)
        {
            Error("AppLogger", "Failed to open crash directory in Explorer", ex);
        }
    }
}
