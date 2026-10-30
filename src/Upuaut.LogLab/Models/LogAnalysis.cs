namespace Upuaut.LogLab.Models;

public enum LogScenarioCategory
{
    Crash,
    Installation,
    Update,
    Authentication,
    Security,
    Network,
    Storage,
    Service,
    Performance,
    Maintenance,
    Success,
    Failure,
    Warning,
    Operational,
    Unclassified
}

public enum RuleMatchStrength { Weak, Moderate, Strong, NoRuleMatched }

public sealed record LogEvidence(string Field, string Value);

public sealed record LogEntryAnalysis(
    int EntryIndex,
    LogScenarioCategory Category,
    string Headline,
    string Explanation,
    RuleMatchStrength MatchStrength,
    IReadOnlyList<string> Tags,
    IReadOnlyList<LogEvidence> Evidence,
    IReadOnlyList<string> Recommendations);

public sealed record LogCategoryCount(LogScenarioCategory Category, int Count);

public sealed record LogAnalysisReport(
    int EntryCount,
    int ClassifiedCount,
    int ErrorCount,
    int WarningCount,
    IReadOnlyList<LogCategoryCount> CategoryCounts,
    IReadOnlyDictionary<int, LogEntryAnalysis> Entries);
