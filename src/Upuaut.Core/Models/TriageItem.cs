namespace Upuaut.Core.Models;

/// <summary>
/// Represents a correlated triage record pairing a system or imported log entry
/// with temporal packet activity, nearby log neighbors, and calculated proximity.
/// </summary>
public sealed record TriageItem(
    LogRecord Log,
    PacketFrame? NearestPacket,
    TimeSpan? TimeDelta,
    int NearbyPacketCount,
    int ProximityScore,
    string SourceLabel = "Windows event",
    LogRecord? NearestRelatedLog = null,
    TimeSpan? RelatedLogDelta = null,
    IReadOnlyList<string>? PacketMatchBasis = null,
    int RelatedLogCount = 0,
    int PacketCandidatesReviewed = 0)
{
    public IReadOnlyList<string> PacketMatchBasis { get; init; } = PacketMatchBasis ?? Array.Empty<string>();
}
