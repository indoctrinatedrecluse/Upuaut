namespace Upuaut.LogLab.Models;

public enum LogSequenceKind { RepeatedFailure, WarningEscalated, ErrorFollowedByRecovery }

public sealed record LogSequenceAnalysisOptions(int WindowMinutes = 15, bool SameComponentOnly = false);

public sealed record LogSequenceFinding(
    LogSequenceKind Kind,
    string Headline,
    string Explanation,
    IReadOnlyList<int> EntryIndices,
    IReadOnlyList<int> SourceLines,
    DateTimeOffset? StartedAt,
    DateTimeOffset? EndedAt,
    string Evidence);

public sealed record LogReportOptions(
    bool IncludeSummary = true,
    bool IncludeCategorySummary = true,
    bool IncludeSequenceFindings = true,
    bool IncludeNotableEntries = true,
    bool IncludeParserNotes = true,
    bool IncludeRecommendations = true,
    bool IncludeTimeline = true);
