namespace Upuaut.LogLab.Models;

public enum LogDocumentFormat
{
    PlainText,
    Json,
    JsonLines,
    Xml,
    Csv,
    Ini,
    KeyValue,
    Syslog,
    WebAccess,
    WindowsEventXml,
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

public enum LogContentKind
{
    Text,
    MixedTextAndBinary,
    BinaryLike
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
    IReadOnlyList<string> Warnings,
    LogContentKind ContentKind = LogContentKind.Text)
{
    public string FileExtension => Path.GetExtension(FileName).ToLowerInvariant();

    public string ExtensionTypeName => FileExtension switch
    {
        ".txt" => "Text",
        ".log" => "Log",
        ".json" => "JSON",
        ".jsonl" => "JSON Lines",
        ".ndjson" => "NDJSON",
        ".xml" => "XML",
        ".evtx" => "Windows Event",
        ".hex" => "Hex dump",
        ".sav" => "Save",
        ".sln" => "Solution",
        ".bin" => "Binary",
        ".dat" => "Data",
        ".csv" => "CSV",
        ".ini" => "INI",
        ".conf" => "Configuration",
        ".cfg" => "Configuration",
        ".yaml" or ".yml" => "YAML",
        ".toml" => "TOML",
        ".logfmt" => "Logfmt",
        ".syslog" => "Syslog",
        ".out" => "Output",
        ".err" => "Error output",
        _ when FileExtension.Length > 1 => FileExtension[1..].ToUpperInvariant(),
        _ => string.Empty
    };

    public string FileTypeLabel
    {
        get
        {
            var formatName = Format switch
            {
                LogDocumentFormat.PlainText => "Plain text",
                LogDocumentFormat.JsonLines => "JSON Lines",
                LogDocumentFormat.WindowsEventXml => "Windows Event XML",
                LogDocumentFormat.WebAccess => "Web access",
                LogDocumentFormat.KeyValue => "Key/value",
                LogDocumentFormat.CustomProfile => "Custom profile",
                _ => Format.ToString().ToUpperInvariant()
            };
            if (FileExtension.Length > 1)
            {
                var fileKind = FileExtension switch
                {
                    ".hex" => "Hex dump file",
                    ".sav" => "Save file",
                    ".sln" => "Solution file",
                    ".bin" => "Binary file",
                    ".dat" => "Data file",
                    _ => $"{ExtensionTypeName} type log file"
                };
                return $"{fileKind} ({FileExtension})";
            }
            return $"{formatName} log file (no extension)";
        }
    }
}

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
