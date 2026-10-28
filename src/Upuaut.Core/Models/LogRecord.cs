namespace Upuaut.Core.Models;

public record LogRecord
{
    public long RecordId { get; init; }
    public int EventId { get; init; }
    public string ProviderName { get; init; } = string.Empty;
    public string Channel { get; init; } = string.Empty;
    public LogSeverityLevel Level { get; init; } = LogSeverityLevel.Information;
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string Message { get; init; } = string.Empty;
    public int? ProcessId { get; init; }
    public int? ThreadId { get; init; }
    public string? ComputerName { get; init; }
    public string? TaskCategory { get; init; }
    public string? Keywords { get; init; }
    public string? RawXml { get; init; }
    public bool IsRealTimeEtw { get; init; }
    public LogExplanation? Explanation { get; init; }
}
