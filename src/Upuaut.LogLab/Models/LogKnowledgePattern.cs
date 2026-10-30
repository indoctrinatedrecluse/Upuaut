namespace Upuaut.LogLab.Models;

/// <summary>A deterministic, source-attributed training example for local scenario ranking.</summary>
public sealed record LogKnowledgePattern(
    string Id,
    LogScenarioCategory Category,
    string Headline,
    string Explanation,
    IReadOnlyList<string> Signals,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> Recommendations,
    string SourceName,
    string SourceUrl,
    string Example);
