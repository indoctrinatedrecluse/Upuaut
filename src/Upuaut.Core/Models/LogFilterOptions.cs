namespace Upuaut.Core.Models;

public enum LogTimeRange
{
    LastHour,
    Last24Hours,
    Last7Days,
    Last30Days,
    AllTime,
    Custom
}

public class LogFilterOptions
{
    public string Channel { get; set; } = "System";
    
    // Default to Critical, Error, Warning as requested
    public HashSet<LogSeverityLevel> Levels { get; set; } = new()
    {
        LogSeverityLevel.Critical,
        LogSeverityLevel.Error,
        LogSeverityLevel.Warning
    };

    public LogTimeRange TimeRange { get; set; } = LogTimeRange.Last24Hours;
    public DateTime? CustomStartTime { get; set; }
    public DateTime? CustomEndTime { get; set; }

    public int? EventId { get; set; }
    public string? ProviderName { get; set; }
    public string? SearchText { get; set; }
    public int MaxEvents { get; set; } = 1000;
}
