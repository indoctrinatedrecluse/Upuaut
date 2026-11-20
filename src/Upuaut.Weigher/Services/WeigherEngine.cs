using System.Globalization;
using System.Text;
using System.Text.Json;
using Upuaut.Core.Interfaces;
using Upuaut.Core.Models;

namespace Upuaut.Weigher.Services;

/// <summary>
/// Core implementation of the Scales of Ma'at cross-source correlation engine.
/// Evaluates temporal proximity and shared entity identifiers between system logs,
/// imported log files, and live or replayed network packets.
/// </summary>
public sealed class WeigherEngine : IWeigherEngine
{
    public const int DefaultCorrelationWindowMilliseconds = 2500;
    public const int MaximumPacketCandidatesPerEntry = 256;
    private const int MaximumSearchCharacters = 32_768;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public IReadOnlyList<TriageItem> Correlate(
        IEnumerable<LogRecord> logs,
        IEnumerable<PacketFrame> packets,
        TimeSpan? correlationWindow = null)
    {
        ArgumentNullException.ThrowIfNull(logs);
        ArgumentNullException.ThrowIfNull(packets);

        var windowMs = correlationWindow?.TotalMilliseconds ?? DefaultCorrelationWindowMilliseconds;
        var orderedPackets = packets.OrderBy(p => AsUtc(p.Timestamp)).ToList();
        var logList = logs.ToList();
        var orderedLogs = logList.OrderBy(l => AsUtc(l.Timestamp)).ToList();

        var results = new List<TriageItem>(logList.Count);
        foreach (var log in logList)
        {
            results.Add(CorrelateSingle(log, orderedLogs, orderedPackets, windowMs));
        }

        return results;
    }

    public IReadOnlyList<CorrelatedEvent> Analyze(
        IEnumerable<LogRecord> logRecords,
        IEnumerable<PacketFrame> packetFrames,
        TimeSpan correlationWindow)
    {
        var triageItems = Correlate(logRecords, packetFrames, correlationWindow);
        return triageItems
            .Where(item => item.NearestPacket is not null || item.NearestRelatedLog is not null)
            .Select(item => new CorrelatedEvent
            {
                Id = Guid.NewGuid().ToString("N"),
                Timestamp = item.Log.Timestamp,
                Severity = item.Log.Level,
                Title = item.Log.Explanation?.Summary ?? (item.Log.EventId > 0 ? $"Event {item.Log.EventId} ({item.Log.ProviderName})" : item.Log.ProviderName),
                Description = item.Log.Message,
                RootCauseHint = item.NearestPacket is { } p
                    ? $"{p.Protocol} frame {p.SourceIp}:{p.SourcePort} -> {p.DestinationIp}:{p.DestinationPort} ({item.ProximityScore}% temporal proximity; delta: {item.TimeDelta?.TotalMilliseconds:+0;-0;0} ms)"
                    : (item.NearestRelatedLog is { } r ? $"Related log from {r.ProviderName} ({Math.Abs(item.RelatedLogDelta?.TotalMilliseconds ?? 0):N0} ms away)" : string.Empty),
                LogSource = item.Log,
                PacketSource = item.NearestPacket,
                ProcessContext = item.NearestPacket?.ProcessName ?? (item.Log.ProcessId.HasValue ? $"PID {item.Log.ProcessId}" : null)
            })
            .ToList();
    }

    public string ExportCaseJson(TriageCase triageCase)
    {
        ArgumentNullException.ThrowIfNull(triageCase);

        // Sanitize raw binary frames from the saved case payload to preserve disk budget
        var sanitizedItems = triageCase.Items.Select(item =>
            item with
            {
                NearestPacket = item.NearestPacket is { } p
                    ? p with { RawData = null, Payload = null }
                    : null
            }).ToList();

        var sanitizedCase = new TriageCase(
            triageCase.SavedAt,
            triageCase.CaseTitle,
            triageCase.TimeWindow,
            triageCase.Channel,
            triageCase.CustomStartTime,
            triageCase.CustomEndTime,
            triageCase.ReviewedPackets,
            sanitizedItems,
            triageCase.Notes,
            triageCase.IncludeInformational);

        return JsonSerializer.Serialize(sanitizedCase, JsonOptions);
    }

    public TriageCase DeserializeCaseJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("Case JSON cannot be empty.", nameof(json));

        return JsonSerializer.Deserialize<TriageCase>(json, JsonOptions)
            ?? throw new InvalidDataException("Failed to deserialize valid Upuaut case structure.");
    }

    public string ExportCaseCsv(IEnumerable<TriageItem> items, IReadOnlyDictionary<string, string>? notes = null)
    {
        ArgumentNullException.ThrowIfNull(items);

        var rows = new List<string>
        {
            "Timestamp,Channel,Level,Provider,SourceLabel,SourceFile,EventId,RelatedProvider,RelatedLogCount,RelatedDeltaMs,PacketMatchBasis,PacketCandidatesReviewed,PacketProtocol,Source,Destination,DeltaMs,NearbyFrames,TemporalProximity,Note"
        };

        var invariant = CultureInfo.InvariantCulture;
        foreach (var item in items)
        {
            var noteKey = $"{item.Log.Channel}:{item.Log.RecordId}:{item.Log.EventId}";
            var note = notes?.GetValueOrDefault(noteKey) ?? string.Empty;

            rows.Add(string.Join(",",
                Q(item.Log.Timestamp.ToUniversalTime().ToString("O", invariant)),
                Q(item.Log.Channel),
                Q(item.Log.Level.ToString()),
                Q(item.Log.ProviderName),
                Q(item.SourceLabel),
                Q(item.Log.SourceFile),
                item.Log.EventId.ToString(invariant),
                Q(item.NearestRelatedLog?.ProviderName),
                item.RelatedLogCount.ToString(invariant),
                item.RelatedLogDelta?.TotalMilliseconds.ToString("F1", invariant) ?? "",
                Q(string.Join("; ", item.PacketMatchBasis)),
                item.PacketCandidatesReviewed.ToString(invariant),
                Q(item.NearestPacket?.TransportProtocol.ToString() ?? item.NearestPacket?.Protocol.ToString()),
                Q(item.NearestPacket?.SourceIp + (item.NearestPacket?.SourcePort is { } sp ? $":{sp}" : "")),
                Q(item.NearestPacket?.DestinationIp + (item.NearestPacket?.DestinationPort is { } dp ? $":{dp}" : "")),
                item.TimeDelta?.TotalMilliseconds.ToString("F1", invariant) ?? "",
                item.NearbyPacketCount.ToString(invariant),
                item.ProximityScore.ToString(invariant),
                Q(note)));
        }

        return string.Join(Environment.NewLine, rows);
    }

    private static TriageItem CorrelateSingle(
        LogRecord log,
        IReadOnlyList<LogRecord> logs,
        IReadOnlyList<PacketFrame> packets,
        double windowMs)
    {
        var eventTime = AsUtc(log.Timestamp);
        var from = LowerBound(packets, eventTime.AddMilliseconds(-windowMs));
        var to = UpperBound(packets, eventTime.AddMilliseconds(windowMs));
        var insertion = LowerBound(packets, eventTime);
        var searchable = BuildSearchableLog(log);

        var candidates = new List<(PacketFrame Packet, TimeSpan Delta, IReadOnlyList<string> Basis)>(
            Math.Min(MaximumPacketCandidatesPerEntry, Math.Max(0, to - from)));

        var left = Math.Min(insertion - 1, to - 1);
        var right = Math.Max(insertion, from);

        while (candidates.Count < MaximumPacketCandidatesPerEntry && (left >= from || right < to))
        {
            var takeLeft = left >= from && (right >= to || Math.Abs((AsUtc(packets[left].Timestamp) - eventTime).Ticks) <= Math.Abs((AsUtc(packets[right].Timestamp) - eventTime).Ticks));
            var packet = takeLeft ? packets[left--] : packets[right++];
            var delta = AsUtc(packet.Timestamp) - eventTime;
            candidates.Add((packet, delta, PacketMatchBasis(log.ProcessId, searchable, packet)));
        }

        var nearest = candidates
            .OrderByDescending(candidate => candidate.Basis.Count)
            .ThenBy(candidate => Math.Abs(candidate.Delta.TotalMilliseconds))
            .FirstOrDefault();

        var logFrom = LowerBoundLog(logs, eventTime.AddMilliseconds(-windowMs));
        var logTo = UpperBoundLog(logs, eventTime.AddMilliseconds(windowMs));
        var relatedCount = Math.Max(0, logTo - logFrom - 1);
        var related = FindNearestRelatedLog(log, logs, logFrom, logTo, eventTime);

        var proximityScore = nearest.Packet is null
            ? 0
            : Math.Max(0, (int)Math.Round(100 * (1 - Math.Abs(nearest.Delta.TotalMilliseconds) / windowMs)));

        return new TriageItem(
            Log: log,
            NearestPacket: nearest.Packet,
            TimeDelta: nearest.Packet is null ? null : nearest.Delta,
            NearbyPacketCount: Math.Max(0, to - from),
            ProximityScore: proximityScore,
            SourceLabel: SourceLabelFor(log),
            NearestRelatedLog: related.Log,
            RelatedLogDelta: related.Delta,
            PacketMatchBasis: nearest.Basis,
            RelatedLogCount: relatedCount,
            PacketCandidatesReviewed: candidates.Count);
    }

    private static (LogRecord? Log, TimeSpan? Delta) FindNearestRelatedLog(
        LogRecord log,
        IReadOnlyList<LogRecord> logs,
        int from,
        int to,
        DateTime eventTime)
    {
        var right = from;
        while (right < to && ReferenceEquals(logs[right], log)) right++;
        var left = from - 1;
        var before = left >= from ? logs[left] : null;
        var after = right < to ? logs[right] : null;

        if (before is null && after is null) return (null, null);

        var beforeDelta = before is null ? (TimeSpan?)null : AsUtc(before.Timestamp) - eventTime;
        var afterDelta = after is null ? (TimeSpan?)null : AsUtc(after.Timestamp) - eventTime;

        if (beforeDelta is null) return (after, afterDelta);
        if (afterDelta is null || Math.Abs(beforeDelta.Value.Ticks) <= Math.Abs(afterDelta.Value.Ticks))
            return (before, beforeDelta);

        return (after, afterDelta);
    }

    private static string BuildSearchableLog(LogRecord log)
    {
        var relevantFields = log.EventData.Concat(log.NormalizedEventData)
            .Where(pair => new[] { "ip", "host", "dns", "domain", "endpoint", "address", "process", "computer" }
                .Any(term => pair.Key.Contains(term, StringComparison.OrdinalIgnoreCase)))
            .Take(64)
            .Select(pair => pair.Value);

        var text = string.Join(" ", new[] { log.Message, log.ProviderName }.Concat(relevantFields));
        return text.Length <= MaximumSearchCharacters ? text : text[..MaximumSearchCharacters];
    }

    private static IReadOnlyList<string> PacketMatchBasis(int? processId, string searchable, PacketFrame packet)
    {
        var matches = new List<string>();
        if (processId is { } pid && packet.ProcessId == pid)
            matches.Add($"Process ID {pid}");

        foreach (var endpoint in new[] { packet.SourceIp, packet.DestinationIp }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (searchable.Contains(endpoint, StringComparison.OrdinalIgnoreCase))
                matches.Add($"Endpoint {endpoint}");
        }

        if (!string.IsNullOrWhiteSpace(packet.DnsQueryName) &&
            searchable.Contains(packet.DnsQueryName, StringComparison.OrdinalIgnoreCase))
        {
            matches.Add($"DNS {packet.DnsQueryName}");
        }

        if (!string.IsNullOrWhiteSpace(packet.ProcessName) &&
            searchable.Contains(packet.ProcessName, StringComparison.OrdinalIgnoreCase))
        {
            matches.Add($"Process {packet.ProcessName}");
        }

        return matches;
    }

    private static int LowerBoundLog(IReadOnlyList<LogRecord> logs, DateTime timestamp)
    {
        var low = 0;
        var high = logs.Count;
        while (low < high)
        {
            var mid = low + (high - low) / 2;
            if (AsUtc(logs[mid].Timestamp) < timestamp) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    private static int UpperBoundLog(IReadOnlyList<LogRecord> logs, DateTime timestamp)
    {
        var low = 0;
        var high = logs.Count;
        while (low < high)
        {
            var mid = low + (high - low) / 2;
            if (AsUtc(logs[mid].Timestamp) <= timestamp) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    private static int LowerBound(IReadOnlyList<PacketFrame> packets, DateTime timestamp)
    {
        var low = 0;
        var high = packets.Count;
        while (low < high)
        {
            var mid = low + (high - low) / 2;
            if (AsUtc(packets[mid].Timestamp) < timestamp) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    private static int UpperBound(IReadOnlyList<PacketFrame> packets, DateTime timestamp)
    {
        var low = 0;
        var high = packets.Count;
        while (low < high)
        {
            var mid = low + (high - low) / 2;
            if (AsUtc(packets[mid].Timestamp) <= timestamp) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    private static DateTime AsUtc(DateTime value) => value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();

    private static string SourceLabelFor(LogRecord log) =>
        log.Channel.StartsWith("Imported log:", StringComparison.Ordinal)
            ? $"Imported / {log.SourceFile ?? "log file"}"
            : $"Windows / {log.Channel}";

    /// <summary>
    /// Escapes and quotes CSV values, prepending an apostrophe if the value begins with a formula trigger character.
    /// </summary>
    private static string Q(string? value)
    {
        var text = value ?? string.Empty;
        if (text.TrimStart(' ', '\t', '\r', '\n').FirstOrDefault() is '=' or '+' or '-' or '@')
            text = "'" + text;

        return "\"" + text.Replace("\"", "\"\"") + "\"";
    }
}
