namespace Upuaut.Core.Models;

/// <summary>
/// Represents an aggregated cluster of repetitive log records sharing an identical failure signature.
/// Collapses thousands of redundant spam events into a single actionable failure mode.
/// </summary>
public record EventCluster
{
    public string Fingerprint { get; init; } = string.Empty;
    public string ProviderName { get; init; } = string.Empty;
    public int EventId { get; init; }
    public LogSeverityLevel Level { get; init; } = LogSeverityLevel.Information;
    public int Count { get; init; }
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; init; }
    public LogRecord Exemplar { get; init; } = default!;
    public IReadOnlyList<string> DistinctProcesses { get; init; } = Array.Empty<string>();
    public string GroupingReason { get; init; } = "Same provider, event ID, severity, and normalized message prefix.";
    public TimeSpan Duration => LastSeen - FirstSeen;
}
