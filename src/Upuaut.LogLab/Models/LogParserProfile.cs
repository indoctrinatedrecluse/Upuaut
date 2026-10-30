namespace Upuaut.LogLab.Models;

/// <summary>A bounded line-oriented custom parser; patterns are evaluated with a short timeout.</summary>
public sealed record LogParserProfile(
    string Name,
    string Description,
    string LinePattern,
    IReadOnlyList<LogFieldPattern> Fields);

public sealed record LogFieldPattern(string Name, string Pattern, string GroupName = "value");

public sealed record LogProfileApplyResult(LogDocument Document, int MatchedLines, int SourceLineCount);

public static class BuiltInLogParserProfiles
{
    public static IReadOnlyList<LogParserProfile> All { get; } =
    [
        new(".NET Console Log", "Parses the default Microsoft.Extensions.Logging console format.",
            @"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*[+-]\d{2}:\d{2})?\s+(?:trce|dbug|info|warn|warning|fail|error|crit|critical)\s+.+$",
            [new("Timestamp", @"^(?<value>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*[+-]\d{2}:\d{2})?)"),
             new("Severity", @"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*[+-]\d{2}:\d{2})?\s+(?<value>trce|dbug|info|warn|warning|fail|error|crit|critical)\b"),
             new("Source", @"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*[+-]\d{2}:\d{2})?\s+\S+\s+(?<value>[^\[]+?)(?:\[\d+\])?:"),
             new("EventId", @"\[(?<value>\d+)\]"),
             new("Message", @":\s*(?<value>.*)$")]),
        new("Apache Error Log", "Parses common Apache error-log timestamps, severity labels, client hints, and messages.",
            @"^\[[^\]]+\]\s+\[[^\]]*?(?:emerg|alert|crit|error|warn|notice|info|debug)\]\s+.*$",
            [new("Timestamp", @"^\[(?<value>[^\]]+)\]"),
             new("Severity", @"^\[[^\]]+\]\s+\[[^\]]*?(?<value>emerg|alert|crit|error|warn|notice|info|debug)\]"),
             new("Source", @"\[client (?<value>[^\]]+)\]"),
             new("Message", @"^(?:\[[^\]]+\]\s+)+(?<value>.*)$")]),
        new("Nginx Access Errors", "Parses Nginx/combined access rows with 4xx and 5xx response codes.",
            @"^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+\x22[A-Z]+\s+[^\x22]+\x22\s+[45]\d{2}\b.*$",
            [new("Source", @"^(?<value>\S+)"),
             new("Request", @"\x22(?<value>[A-Z]+\s+[^\x22]+)\x22"),
             new("Severity", @"\x22\s+(?<value>[45]\d{2})\b"),
             new("HttpStatus", @"\x22\s+(?<value>[45]\d{2})\b"),
             new("TimestampText", @"\[(?<value>[^\]]+)\]")]),
        new("RFC 3164 Syslog", "Parses classic month/day/time syslog lines; timestamps omit a year and are retained as text.",
            @"^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+.+$",
            [new("SyslogPriority", @"^<(?<value>\d{1,3})>"),
             new("SyslogTimestamp", @"^(?:<\d{1,3}>)?(?<value>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
             new("Source", @"^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?<value>\S+)"),
             new("Message", @"^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(?:\[\d+\])?:\s*(?<value>.*)$")])
    ];
}
