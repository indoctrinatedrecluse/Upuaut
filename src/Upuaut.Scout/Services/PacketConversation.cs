using Upuaut.Core.Models;

namespace Upuaut.Scout.Services;

public sealed record PacketConversation(string Key, string EndpointA, string EndpointB, NetworkProtocol Protocol,
    int PacketCount, long Bytes, DateTime FirstSeen, DateTime LastSeen, IReadOnlyList<PacketFrame> Frames);

public static class PacketConversations
{
    public static IReadOnlyList<PacketConversation> Group(IEnumerable<PacketFrame> frames) => frames
        .Where(f => f.SourcePort.HasValue && f.DestinationPort.HasValue)
        .GroupBy(f =>
        {
            var a = $"{f.SourceIp}:{f.SourcePort}"; var b = $"{f.DestinationIp}:{f.DestinationPort}";
            var ordered = string.CompareOrdinal(a, b) <= 0 ? (a, b) : (b, a);
            return (ordered.Item1, ordered.Item2, f.TransportProtocol == NetworkProtocol.Unknown ? f.Protocol : f.TransportProtocol);
        })
        .Select(g => new PacketConversation($"{g.Key.Item1}|{g.Key.Item2}|{g.Key.Item3}", g.Key.Item1, g.Key.Item2,
            g.Key.Item3, g.Count(), g.Sum(f => (long)f.TotalLength), g.Min(f => f.Timestamp), g.Max(f => f.Timestamp),
            g.OrderBy(f => f.Timestamp).ToList()))
        .OrderByDescending(g => g.LastSeen).ToList();
}
