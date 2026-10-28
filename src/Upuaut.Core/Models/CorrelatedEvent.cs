namespace Upuaut.Core.Models;

public record CorrelatedEvent
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public LogSeverityLevel Severity { get; init; } = LogSeverityLevel.Warning;
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string RootCauseHint { get; init; } = string.Empty;
    public LogRecord? LogSource { get; init; }
    public PacketFrame? PacketSource { get; init; }
    public string? ProcessContext { get; init; }
}
