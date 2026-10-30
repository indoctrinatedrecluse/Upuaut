namespace Upuaut.LogLab.Models;

public sealed record LogTimelineBucket(
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    int TotalCount,
    int WarningCount,
    int ErrorCount,
    IReadOnlyList<int> EntryIndices);

public sealed record LogTimelineReport(
    int RequestedIntervalMinutes,
    int EffectiveIntervalMinutes,
    int EntriesWithTimestamps,
    int EntriesWithoutTimestamps,
    IReadOnlyList<LogTimelineBucket> Buckets);
