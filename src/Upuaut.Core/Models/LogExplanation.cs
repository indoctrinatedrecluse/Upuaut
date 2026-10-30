namespace Upuaut.Core.Models;

public enum TriageSeverity
{
    BenignNoise,   // Safe to ignore, normal Windows telemetry by design
    Low,           // Minor inconvenience or cosmetic issue
    Medium,        // Network glitch, service timeout, or transient error
    High,          // Application crash, disk warning, or permission block
    Critical       // Kernel crash, BSOD, hardware fault, or unrecoverable error
}

public record LogExplanation
{
    public string Headline { get; init; } = string.Empty;
    public string Category { get; init; } = "Unclassified";
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<EvidenceObservation> Evidence { get; init; } = Array.Empty<EvidenceObservation>();
    /// <summary>Strength of the matching deterministic rule, not probability that a cause is true.</summary>
    public int RuleMatchStrength { get; init; }
    public string MatchBasis { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public TriageSeverity TriageRating { get; init; } = TriageSeverity.Medium;
    public string? Subsystem { get; init; }
    public string? ImpactAssessment { get; init; }
    public string? ForensicFixCommand { get; init; }
    public IReadOnlyList<string> ProbableCauses { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> TechnicalDetails { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> DecodedFields { get; init; } = new Dictionary<string, string>();
    public bool IsCuratedKnowledge { get; init; }
    public string? DecodedStatusCode { get; init; }
    public string? StatusMeaning { get; init; }
}

public sealed record EvidenceObservation(string Label, string Value, string Interpretation);
