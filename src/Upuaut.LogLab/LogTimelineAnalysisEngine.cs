using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>Creates bounded UTC time buckets for interactive navigation and trend reports.</summary>
public sealed class LogTimelineAnalysisEngine : ILogTimelineAnalysisEngine
{
    private const int MaximumBuckets = 240;

    public LogTimelineReport Analyze(LogDocument document, int intervalMinutes = 5)
    {
        ArgumentNullException.ThrowIfNull(document);
        var requested = Math.Clamp(intervalMinutes, 1, 1440);
        var stamped = document.Entries.Where(entry => entry.Timestamp.HasValue).ToArray();
        if (stamped.Length == 0) return new LogTimelineReport(requested, requested, 0, document.Entries.Count, []);

        var minimum = stamped.Min(entry => entry.Timestamp!.Value).ToUniversalTime();
        var maximum = stamped.Max(entry => entry.Timestamp!.Value).ToUniversalTime();
        var rangeMinutes = Math.Max(0, (maximum - minimum).TotalMinutes);
        var effective = Math.Max(requested, (int)Math.Ceiling(rangeMinutes / (MaximumBuckets - 1)));
        var widthTicks = TimeSpan.FromMinutes(effective).Ticks;
        var firstBucket = minimum.UtcTicks / widthTicks;
        var lastBucket = maximum.UtcTicks / widthTicks;
        var entriesByBucket = stamped.GroupBy(entry => entry.Timestamp!.Value.ToUniversalTime().UtcTicks / widthTicks)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var buckets = new List<LogTimelineBucket>((int)Math.Min(MaximumBuckets, lastBucket - firstBucket + 1));
        for (var bucket = firstBucket; bucket <= lastBucket && buckets.Count < MaximumBuckets; bucket++)
        {
            entriesByBucket.TryGetValue(bucket, out var entries);
            entries ??= [];
            var start = new DateTimeOffset(bucket * widthTicks, TimeSpan.Zero);
            buckets.Add(new LogTimelineBucket(start, start.AddTicks(widthTicks), entries.Length,
                entries.Count(entry => entry.Severity == LogEntrySeverity.Warning),
                entries.Count(entry => entry.Severity is LogEntrySeverity.Error or LogEntrySeverity.Critical),
                entries.Select(entry => entry.Index).ToArray()));
        }
        return new LogTimelineReport(requested, effective, stamped.Length, document.Entries.Count - stamped.Length, buckets);
    }
}
