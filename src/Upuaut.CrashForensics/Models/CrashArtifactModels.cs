namespace Upuaut.CrashForensics.Models;

public enum CrashArtifactKind
{
    WindowsMinidump,
    WindowsKernelDump,
    WindowsErrorReport,
    Unknown
}

public sealed record CrashExceptionEvidence(uint Code, ulong Address, uint ThreadId, IReadOnlyList<ulong> Parameters)
{
    public string CodeText => $"0x{Code:X8}";
}

public sealed record CrashModuleEvidence(string Name, ulong BaseAddress, uint ImageSize, uint TimeDateStamp);

public sealed record CrashThreadEvidence(uint Id, ulong TebAddress, ulong StackStart, ulong StackSize);

public sealed record ManagedRuntimeEvidence(string Flavor, string Version, IReadOnlyList<ManagedThreadEvidence> Threads);

public sealed record ManagedThreadEvidence(uint OsThreadId, int ManagedThreadId, bool IsAlive, IReadOnlyList<string> Frames);

public sealed record CrashFinding(string Code, string Headline, string Explanation, IReadOnlyList<string> Checks);

public sealed record CrashLogEvidence(int SourceLine, string Severity, string Message, string? Headline, string? Explanation, string? SourceUrl);

public sealed record CrashLogContext(string FileName, string SourcePath, int SourceLine, DateTimeOffset? Timestamp, string Severity, string Headline, string Explanation, string Message);

public sealed record CrashAnalysisResult(
    string FileName,
    string SourcePath,
    long FileSizeBytes,
    CrashArtifactKind Kind,
    string Summary,
    string? Architecture,
    string? OperatingSystem,
    DateTimeOffset? DumpTimestampUtc,
    uint? ProcessId,
    CrashExceptionEvidence? Exception,
    IReadOnlyList<CrashModuleEvidence> Modules,
    IReadOnlyList<CrashThreadEvidence> Threads,
    IReadOnlyList<ManagedRuntimeEvidence> ManagedRuntimes,
    IReadOnlyList<CrashFinding> Findings,
    IReadOnlyList<CrashLogEvidence> LogEvidence,
    IReadOnlyDictionary<string, string> ReportFields,
    IReadOnlyList<string> Warnings)
{
    public bool IsKernelDump => Kind == CrashArtifactKind.WindowsKernelDump;
}
