using Upuaut.Core.Models;

namespace Upuaut.UI.Shared;

/// <summary>Shared time window and current evidence selection used when moving between tabs.</summary>
public sealed class InvestigationContext
{
    public LogTimeRange TimeRange { get; private set; } = LogTimeRange.Last24Hours;
    public DateTime? Start { get; private set; } = DateTime.UtcNow.AddHours(-24);
    public DateTime? End { get; private set; } = DateTime.UtcNow;
    public LogRecord? SelectedLog { get; private set; }
    public PacketFrame? SelectedFrame { get; private set; }
    public void SetRange(LogTimeRange range, DateTime? start = null, DateTime? end = null)
    {
        TimeRange = range;
        End = range == LogTimeRange.Custom && end.HasValue ? end.Value.ToUniversalTime() : DateTime.UtcNow;
        Start = range == LogTimeRange.Custom
            ? start?.ToUniversalTime()
            : range switch { LogTimeRange.LastHour => End.Value.AddHours(-1), LogTimeRange.Last7Days => End.Value.AddDays(-7), LogTimeRange.Last30Days => End.Value.AddDays(-30), LogTimeRange.AllTime => null, _ => End.Value.AddHours(-24) };
    }
    public void Select(LogRecord? log) { SelectedLog = log; }
    public void Select(PacketFrame? frame) { SelectedFrame = frame; }
}
