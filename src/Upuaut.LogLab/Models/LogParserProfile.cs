namespace Upuaut.LogLab.Models;

/// <summary>A bounded line-oriented custom parser; patterns are evaluated with a short timeout.</summary>
public sealed record LogParserProfile(
    string Name,
    string Description,
    string LinePattern,
    IReadOnlyList<LogFieldPattern> Fields);

public sealed record LogFieldPattern(string Name, string Pattern, string GroupName = "value");

public sealed record LogProfileApplyResult(LogDocument Document, int MatchedLines, int SourceLineCount);
