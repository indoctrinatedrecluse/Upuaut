namespace Upuaut.LogLab.Models;

public enum LogSequenceKind { RepeatedFailure, WarningEscalated, ErrorFollowedByRecovery }

public sealed record LogSequenceFinding(
    LogSequenceKind Kind,
    string Headline,
    string Explanation,
    IReadOnlyList<int> EntryIndices,
    IReadOnlyList<int> SourceLines,
    DateTimeOffset? StartedAt,
    DateTimeOffset? EndedAt,
    string Evidence);
