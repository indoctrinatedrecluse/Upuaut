namespace Upuaut.Core.Models;

/// <summary>
/// Persisted investigation snapshot containing case metadata, reviewed log items,
/// temporal packet matches, and analyst notes.
/// </summary>
public sealed class TriageCase
{
    public TriageCase() { }

    public TriageCase(
        DateTimeOffset savedAt,
        string caseTitle,
        LogTimeRange timeWindow,
        string channel,
        DateTime? customStartTime,
        DateTime? customEndTime,
        int reviewedPackets,
        IReadOnlyList<TriageItem> items,
        IReadOnlyDictionary<string, string> notes,
        bool includeInformational = false)
    {
        SavedAt = savedAt;
        CaseTitle = caseTitle;
        TimeWindow = timeWindow;
        Channel = channel;
        CustomStartTime = customStartTime;
        CustomEndTime = customEndTime;
        ReviewedPackets = reviewedPackets;
        Items = items;
        Notes = notes;
        IncludeInformational = includeInformational;
    }

    public DateTimeOffset SavedAt { get; init; }
    public string CaseTitle { get; init; } = "Untitled investigation";
    public LogTimeRange TimeWindow { get; init; }
    public string Channel { get; init; } = "Both";
    public bool IncludeInformational { get; init; }
    public DateTime? CustomStartTime { get; init; }
    public DateTime? CustomEndTime { get; init; }
    public int ReviewedPackets { get; init; }
    public IReadOnlyList<TriageItem> Items { get; init; } = Array.Empty<TriageItem>();
    public IReadOnlyDictionary<string, string> Notes { get; init; } = new Dictionary<string, string>();
}
