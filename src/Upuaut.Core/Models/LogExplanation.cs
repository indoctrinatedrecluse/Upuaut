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
    public string Summary { get; init; } = string.Empty;
    public TriageSeverity TriageRating { get; init; } = TriageSeverity.Medium;
    public IReadOnlyList<string> ProbableCauses { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> TechnicalDetails { get; init; } = Array.Empty<string>();
    public bool IsCuratedKnowledge { get; init; }
    public string? DecodedStatusCode { get; init; }
    public string? StatusMeaning { get; init; }
}
