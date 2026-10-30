using System.Text.RegularExpressions;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public enum LogSyntaxTokenKind
{
    Timestamp,
    Section,
    Key,
    Severity,
    ErrorCode,
    XmlTag,
    String,
    Literal,
    Number,
    Structure
}

public sealed record LogSyntaxToken(int Start, int Length, LogSyntaxTokenKind Kind);

/// <summary>Lightweight best-effort token coloring for common log and structured-text syntax.</summary>
public sealed class LogSyntaxHighlighter
{
    public const int MaximumHighlightCharacters = 300_000;
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly Regex TokenPattern = new(
        """(?<section>^\s*\[[^\]\r\n]+\]\s*$)|(?<timestamp>\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b)|(?<code>\b(?:0x[0-9a-f]{4,16}|(?:error|exception|status|code)(?:[_:=#-][A-Z0-9_-]+)+)\b)|(?<xmltag></?[A-Za-z_][\w:.-]*)|(?<key>(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_][A-Za-z0-9_.-]*)(?=\s*[=:]))|(?<severity>\b(?:trace|verbose|debug|info|information|notice|warn|warning|error|err|fatal|critical|success|succeeded|failed|failure|exception|crash)\b)|(?<literal>\b(?:true|false|null)\b)|(?<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?<number>\b\d+(?:\.\d+)?\b)|(?<structure>[{}\[\](),:])""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.Multiline,
        MatchTimeout);

    public IReadOnlyList<LogSyntaxToken> Tokenize(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > MaximumHighlightCharacters) return [];
        try
        {
            var tokens = new List<LogSyntaxToken>();
            foreach (Match match in TokenPattern.Matches(text))
            {
                var kind = GetKind(match);
                if (kind is { } tokenKind) tokens.Add(new LogSyntaxToken(match.Index, match.Length, tokenKind));
            }
            return tokens;
        }
        catch (RegexMatchTimeoutException)
        {
            // Highlighting must never block editing; the caller falls back to ordinary text.
            return [];
        }
    }

    private static LogSyntaxTokenKind? GetKind(Match match)
    {
        if (match.Groups["section"].Success) return LogSyntaxTokenKind.Section;
        if (match.Groups["timestamp"].Success) return LogSyntaxTokenKind.Timestamp;
        if (match.Groups["code"].Success) return LogSyntaxTokenKind.ErrorCode;
        if (match.Groups["xmltag"].Success) return LogSyntaxTokenKind.XmlTag;
        if (match.Groups["key"].Success) return LogSyntaxTokenKind.Key;
        if (match.Groups["severity"].Success) return LogSyntaxTokenKind.Severity;
        if (match.Groups["literal"].Success) return LogSyntaxTokenKind.Literal;
        if (match.Groups["string"].Success) return LogSyntaxTokenKind.String;
        if (match.Groups["number"].Success) return LogSyntaxTokenKind.Number;
        if (match.Groups["structure"].Success) return LogSyntaxTokenKind.Structure;
        return null;
    }
}
