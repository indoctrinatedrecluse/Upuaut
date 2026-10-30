namespace Upuaut.LogLab.Models;

public enum LogDocumentFormat
{
    PlainText,
    Json,
    JsonLines,
    Xml,
    Csv,
    CustomProfile
}

public enum LogEntrySeverity
{
    Unknown,
    Trace,
    Debug,
    Information,
    Warning,
    Error,
    Critical,
    Success
}

/// <summary>An imported source is retained verbatim; parsing produces a separate, derived view.</summary>
public sealed record LogDocument(
    string FileName,
    string SourcePath,
    long ByteLength,
    string DetectedEncoding,
    LogDocumentFormat Format,
    DateTimeOffset ImportedAtUtc,
    string OriginalText,
    IReadOnlyList<string> SourceLines,
    IReadOnlyList<ParsedLogEntry> Entries,
    IReadOnlyList<string> Warnings);

public sealed record ParsedLogEntry(
    int Index,
    int SourceLine,
    int SourceLineEnd,
    DateTimeOffset? Timestamp,
    LogEntrySeverity Severity,
    string? Source,
    string Message,
    string RawText,
    IReadOnlyDictionary<string, string> Fields,
    string InterpretationBasis);

public sealed record LogSearchOptions(
    string Query,
    LogEntrySeverity? Severity = null,
    string? ComponentContains = null,
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null);
