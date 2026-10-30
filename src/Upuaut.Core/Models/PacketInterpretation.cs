namespace Upuaut.Core.Models;

/// <summary>Deterministic, evidence-grounded interpretation of a captured frame.</summary>
public sealed record PacketInterpretation
{
    public string Category { get; init; } = "Unclassified traffic";
    public string Headline { get; init; } = "Packet observed";
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<EvidenceObservation> Evidence { get; init; } = Array.Empty<EvidenceObservation>();
    public IReadOnlyList<string> Recommendations { get; init; } = Array.Empty<string>();
    /// <summary>Strength of the matching deterministic rule, not probability that an event is malicious.</summary>
    public int RuleMatchStrength { get; init; }
    public string MatchBasis { get; init; } = string.Empty;
}
