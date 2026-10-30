using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Upuaut.Core.Models;

namespace Upuaut.Chronicles.Analytics;

public class EventClusterer
{
    public IReadOnlyList<EventCluster> Cluster(IEnumerable<LogRecord> logs)
    {
        var groups = new Dictionary<string, List<LogRecord>>();

        foreach (var log in logs)
        {
            var fingerprint = GenerateFingerprint(log);
            if (!groups.TryGetValue(fingerprint, out var list))
            {
                list = new List<LogRecord>();
                groups[fingerprint] = list;
            }
            list.Add(log);
        }

        var clusters = new List<EventCluster>();

        foreach (var (fingerprint, groupLogs) in groups)
        {
            var exemplar = groupLogs.OrderByDescending(l => l.Timestamp).First();
            var distinctPids = groupLogs
                .Where(l => l.ProcessId.HasValue)
                .Select(l => l.ProcessId!.Value.ToString())
                .Distinct()
                .Take(5)
                .ToList();

            clusters.Add(new EventCluster
            {
                Fingerprint = fingerprint,
                ProviderName = exemplar.ProviderName,
                EventId = exemplar.EventId,
                Level = exemplar.Level,
                Count = groupLogs.Count,
                FirstSeen = groupLogs.Min(l => l.Timestamp),
                LastSeen = groupLogs.Max(l => l.Timestamp),
                Exemplar = exemplar,
                DistinctProcesses = distinctPids
            });
        }

        return clusters.OrderByDescending(c => c.Count).ThenByDescending(c => c.LastSeen).ToList();
    }

    private static string GenerateFingerprint(LogRecord log)
    {
        // Normalize message: strip variable digits, GUIDs, and timestamps
        var normalized = Regex.Replace(log.Message, @"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b|\b\d+\b", "#");
        var msgPrefix = normalized.Length > 80 ? normalized[..80] : normalized;
        var rawKey = $"{log.ProviderName}_{log.EventId}_{log.Level}_{msgPrefix.Trim()}";

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(rawKey));
        return Convert.ToHexString(hash)[..12];
    }
}
