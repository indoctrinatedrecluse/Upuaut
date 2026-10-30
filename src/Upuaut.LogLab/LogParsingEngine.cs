using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>
/// Best-effort, source-preserving importer for common log and structured-text formats.
/// It never edits the source text and attaches physical line provenance to every entry.
/// </summary>
public sealed class LogParsingEngine : ILogParsingEngine
{
    private const int MaximumEntries = 200_000;
    private const int MaximumSourceLines = 200_000;
    private const int MaximumDetailedWarnings = 250;
    private const int MaximumFieldsPerEntry = 512;
    private const int MaximumFieldValueLength = 16_384;
    private const int MaximumJsonDepth = 64;
    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(150);
    private static readonly Regex TimestampPattern = new(@"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", RegexOptions.Compiled | RegexOptions.CultureInvariant, PatternTimeout);
    private static readonly Regex SeverityPattern = new(@"\b(trace|verbose|debug|info|information|notice|warn|warning|error|err|fatal|critical|success|succeeded|failed|failure|exception|crash)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex ErrorCodePattern = new(@"\b(?:0x[0-9a-f]{4,16}|(?:error|exception|status|code)[ _:=#-]*[A-Z]?[A-Z0-9_-]{2,})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex KeyValuePattern = new(@"(?<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})=(?<value>""(?:\\.|[^""\\])*""|'(?:\\.|[^'\\])*'|[^\s]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant, PatternTimeout);
    private static readonly Regex IniSectionPattern = new(@"^\s*\[(?<name>[^\]]{1,160})\]\s*(?:[;#].*)?$", RegexOptions.Compiled | RegexOptions.CultureInvariant, PatternTimeout);
    private static readonly Regex Syslog5424Pattern = new(@"^<(?<priority>\d{1,3})>(?<version>\d{1,2})\s+(?<timestamp>\S+)\s+(?<host>\S+)\s+(?<app>\S+)\s+(?<procid>\S+)\s+(?<msgid>\S+)\s+(?<structured>(?:\[(?:\\.|[^\]])*\])+|-)(?:\s+(?<message>.*))?$", RegexOptions.Compiled | RegexOptions.CultureInvariant, PatternTimeout);
    private static readonly Regex Syslog3164Pattern = new(@"^(?:<(?<priority>\d{1,3})>)?(?<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host>[A-Za-z0-9_.-]+)\s+(?<app>[A-Za-z0-9_./-]+)(?:\[(?<procid>\d+)\])?:\s*(?<message>.*)$", RegexOptions.Compiled | RegexOptions.CultureInvariant, PatternTimeout);
    private static readonly Regex AccessLogPattern = new(@"^(?<client>\S+)\s+(?<ident>\S+)\s+(?<user>\S+)\s+\[(?<timestamp>[^\]]+)\]\s+""(?<request>[^""]*)""\s+(?<status>\d{3})\s+(?<bytes>\S+)(?:\s+""(?<referer>[^""]*)""\s+""(?<agent>[^""]*)"")?$", RegexOptions.Compiled | RegexOptions.CultureInvariant, PatternTimeout);
    private static readonly HashSet<string> CsvHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "timestamp", "time", "datetime", "date", "level", "severity", "loglevel", "source", "provider",
        "logger", "component", "service", "message", "msg", "description", "event", "eventid", "status",
        "statuscode", "process", "processid", "threadid", "exception", "errorcode", "code", "host", "user"
    };

    public async Task<LogDocument> ImportFileAsync(string path, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Select a log file to import.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        var info = new FileInfo(fullPath);
        if (!info.Exists) throw new FileNotFoundException("The selected log file was not found.", fullPath);
        if (info.Length > ILogParsingEngine.DefaultMaximumFileBytes)
            throw new InvalidDataException($"The selected file is {FormatBytes(info.Length)}. Phase 1 supports files up to {FormatBytes(ILogParsingEngine.DefaultMaximumFileBytes)}.");

        var bytes = await ReadSourceBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        string text;
        string encodingName;
        var warnings = new List<string>();
        try { (text, encodingName) = Decode(bytes); }
        catch (DecoderFallbackException ex)
        {
            (text, encodingName) = DecodeWithReplacement(bytes);
            warnings.Add($"The declared Unicode encoding contains invalid byte sequences; replacement characters were used so the source remains inspectable. {ex.Message}");
        }

        var contentKind = ClassifyContent(text);
        var sourceLines = SplitSourceLines(text, out var sourceLinesTruncated);
        if (sourceLinesTruncated) warnings.Add($"Only the first {MaximumSourceLines:N0} physical source lines are structured for performance. The complete file remains available in raw-source view.");
        var format = LogDocumentFormat.PlainText;
        List<ParsedLogEntry> entries;
        try
        {
            if (contentKind == LogContentKind.BinaryLike)
            {
                warnings.Add("This file appears to contain mostly non-text or encrypted data. Structured parsing was skipped; a decoded raw preview is retained for manual inspection.");
                entries = [];
            }
            else
            {
                if (contentKind == LogContentKind.MixedTextAndBinary)
                    warnings.Add("This file is mostly readable text but contains some unreadable, control, or replacement characters. It remains available for inspection; those spans may be quoted or embedded data, and extracted fields may be incomplete.");
                format = DetectFormat(text, sourceLines);
                entries = format switch
                {
                    LogDocumentFormat.JsonLines => ParseJsonLines(sourceLines, warnings),
                    LogDocumentFormat.Json => ParseJson(text, sourceLines, warnings),
                    LogDocumentFormat.Xml or LogDocumentFormat.WindowsEventXml => ParseXml(text, sourceLines, warnings),
                    LogDocumentFormat.Csv => ParseCsv(sourceLines, warnings),
                    LogDocumentFormat.Ini => ParseIni(sourceLines),
                    LogDocumentFormat.KeyValue => ParseKeyValue(sourceLines),
                    LogDocumentFormat.Syslog => ParseSyslog(sourceLines, warnings),
                    LogDocumentFormat.WebAccess => ParseWebAccess(sourceLines, warnings),
                    _ => ParsePlainText(sourceLines, warnings)
                };
            }

            if (contentKind != LogContentKind.BinaryLike && entries.Count == 0 && sourceLines.Any(line => !string.IsNullOrWhiteSpace(line)))
            {
                warnings.Add("The selected format produced no entries. The original content is shown in raw-text mode.");
                entries = ParsePlainText(sourceLines, warnings);
                format = LogDocumentFormat.PlainText;
            }
            if (warnings.Any(warning => warning.Contains("raw-text mode", StringComparison.OrdinalIgnoreCase)))
                format = LogDocumentFormat.PlainText;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            warnings.Add($"Structured parsing failed ({ex.GetType().Name}: {ex.Message}). The complete decoded source is retained in raw-text mode.");
            entries = ParsePlainText(sourceLines, warnings);
            format = LogDocumentFormat.PlainText;
        }

        return new LogDocument(Path.GetFileName(fullPath), fullPath, bytes.LongLength, encodingName, format,
            DateTimeOffset.UtcNow, text, sourceLines, entries, warnings, contentKind);
    }

    public IReadOnlyList<ParsedLogEntry> Search(LogDocument document, LogSearchOptions options)
    {
        ArgumentNullException.ThrowIfNull(document);
        var query = options.Query?.Trim();
        IEnumerable<ParsedLogEntry> entries = document.Entries;
        if (options.Severity is { } severity) entries = entries.Where(entry => entry.Severity == severity);
        if (!string.IsNullOrWhiteSpace(options.ComponentContains))
            entries = entries.Where(entry => entry.Source?.Contains(options.ComponentContains, StringComparison.OrdinalIgnoreCase) == true ||
                entry.Fields.Any(field => field.Key.Contains("component", StringComparison.OrdinalIgnoreCase) && field.Value.Contains(options.ComponentContains, StringComparison.OrdinalIgnoreCase)));
        if (options.FromUtc is { } from) entries = entries.Where(entry => entry.Timestamp is { } timestamp && timestamp >= from);
        if (options.ToUtc is { } to) entries = entries.Where(entry => entry.Timestamp is { } timestamp && timestamp <= to);
        if (!string.IsNullOrWhiteSpace(query))
        {
            entries = entries.Where(entry =>
                entry.Message.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                entry.Source?.Contains(query, StringComparison.OrdinalIgnoreCase) == true ||
                entry.RawText.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                entry.Fields.Any(field => field.Key.Contains(query, StringComparison.OrdinalIgnoreCase) || field.Value.Contains(query, StringComparison.OrdinalIgnoreCase)));
        }
        return entries.ToArray();
    }

    public string FormatJson(string text)
    {
        using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth, CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        return JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions { WriteIndented = true });
    }

    public string FormatXml(string text)
    {
        using var input = new StringReader(text);
        using var reader = XmlReader.Create(input, SafeXmlSettings());
        var document = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        var settings = new XmlWriterSettings { Indent = true, IndentChars = "  ", OmitXmlDeclaration = document.Declaration is null, NewLineChars = "\n", NewLineHandling = NewLineHandling.Replace };
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using (var writer = XmlWriter.Create(output, settings)) document.Save(writer);
        return output.ToString();
    }

    private static (string Text, string Name) Decode(byte[] bytes)
    {
        if (bytes.Length == 0) return (string.Empty, "UTF-8 (empty file)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) return (new UTF8Encoding(false, true).GetString(bytes, 3, bytes.Length - 3), "UTF-8 (BOM)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE, 0x00, 0x00 })) return (new UTF32Encoding(false, true, true).GetString(bytes, 4, bytes.Length - 4), "UTF-32 LE");
        if (bytes.AsSpan().StartsWith(new byte[] { 0x00, 0x00, 0xFE, 0xFF })) return (new UTF32Encoding(true, true, true).GetString(bytes, 4, bytes.Length - 4), "UTF-32 BE");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE })) return (new UnicodeEncoding(false, false, true).GetString(bytes, 2, bytes.Length - 2), "UTF-16 LE");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFE, 0xFF })) return (new UnicodeEncoding(true, false, true).GetString(bytes, 2, bytes.Length - 2), "UTF-16 BE");
        if (TryDetectBomlessUtf32(bytes, out var utf32BigEndian))
            return (new UTF32Encoding(utf32BigEndian, false, true).GetString(bytes), utf32BigEndian ? "UTF-32 BE (no BOM)" : "UTF-32 LE (no BOM)");
        if (TryDetectBomlessUtf16(bytes, out var utf16BigEndian))
            return (new UnicodeEncoding(utf16BigEndian, false, true).GetString(bytes), utf16BigEndian ? "UTF-16 BE (no BOM)" : "UTF-16 LE (no BOM)");
        try { return (new UTF8Encoding(false, true).GetString(bytes), "UTF-8"); }
        catch (DecoderFallbackException) { return (Encoding.Latin1.GetString(bytes), "ISO-8859-1 fallback"); }
    }

    private static (string Text, string Name) DecodeWithReplacement(byte[] bytes)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) return (Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3), "UTF-8 (BOM, replacement fallback)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE, 0x00, 0x00 })) return (new UTF32Encoding(false, false).GetString(bytes, 4, bytes.Length - 4), "UTF-32 LE (replacement fallback)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0x00, 0x00, 0xFE, 0xFF })) return (new UTF32Encoding(true, false).GetString(bytes, 4, bytes.Length - 4), "UTF-32 BE (replacement fallback)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE })) return (Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2), "UTF-16 LE (replacement fallback)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFE, 0xFF })) return (Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2), "UTF-16 BE (replacement fallback)");
        if (TryDetectBomlessUtf32(bytes, out var utf32BigEndian))
            return (new UTF32Encoding(utf32BigEndian, false).GetString(bytes), utf32BigEndian ? "UTF-32 BE (no BOM, replacement fallback)" : "UTF-32 LE (no BOM, replacement fallback)");
        if (TryDetectBomlessUtf16(bytes, out var utf16BigEndian))
            return ((utf16BigEndian ? Encoding.BigEndianUnicode : Encoding.Unicode).GetString(bytes), utf16BigEndian ? "UTF-16 BE (no BOM, replacement fallback)" : "UTF-16 LE (no BOM, replacement fallback)");
        return (Encoding.UTF8.GetString(bytes), "UTF-8 (replacement fallback)");
    }

    private static string[] SplitSourceLines(string text, out bool truncated)
    {
        var lines = new List<string>(Math.Min(MaximumSourceLines, Math.Max(1, text.Length / 48)));
        var start = 0;
        truncated = false;
        while (lines.Count < MaximumSourceLines)
        {
            var newline = text.IndexOf('\n', start);
            if (newline < 0)
            {
                if (start < text.Length || lines.Count == 0) lines.Add(TrimCarriageReturn(text[start..]));
                return lines.ToArray();
            }
            lines.Add(TrimCarriageReturn(text[start..newline]));
            start = newline + 1;
            if (start == text.Length) return lines.ToArray();
        }
        truncated = start < text.Length;
        return lines.ToArray();
    }

    private static string TrimCarriageReturn(string line) => line.EndsWith('\r') ? line[..^1] : line;

    private static LogContentKind ClassifyContent(string text)
    {
        if (string.IsNullOrEmpty(text)) return LogContentKind.Text;
        long readable = 0;
        long textLike = 0;
        long total = 0;
        foreach (var rune in text.EnumerateRunes())
        {
            total++;
            var category = Rune.GetUnicodeCategory(rune);
            var isLetterOrNumber = category is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or
                    UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or
                    UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark or
                    UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber;
            var isTextLike = isLetterOrNumber || Rune.IsWhiteSpace(rune);
            if (rune != Rune.ReplacementChar && isTextLike) textLike++;
            var isReadable = rune != Rune.ReplacementChar &&
                (isTextLike || category is
                    UnicodeCategory.ConnectorPunctuation or UnicodeCategory.DashPunctuation or UnicodeCategory.OpenPunctuation or
                    UnicodeCategory.ClosePunctuation or UnicodeCategory.InitialQuotePunctuation or UnicodeCategory.FinalQuotePunctuation or
                    UnicodeCategory.OtherPunctuation or UnicodeCategory.MathSymbol or UnicodeCategory.CurrencySymbol or
                    UnicodeCategory.ModifierSymbol or UnicodeCategory.OtherSymbol);
            if (isReadable) readable++;
        }
        var ratio = total == 0 ? 1d : (double)readable / total;
        var textLikeRatio = total == 0 ? 1d : (double)textLike / total;
        if (ratio < 0.75 || textLikeRatio < 0.62) return LogContentKind.BinaryLike;
        return readable == total ? LogContentKind.Text : LogContentKind.MixedTextAndBinary;
    }

    private static bool TryDetectBomlessUtf16(ReadOnlySpan<byte> bytes, out bool bigEndian)
    {
        bigEndian = false;
        if (bytes.Length < 8) return false;
        var length = Math.Min(bytes.Length, 16 * 1024) & ~1;
        var evenZeroes = 0;
        var oddZeroes = 0;
        for (var i = 0; i < length; i++)
        {
            if (bytes[i] == 0) { if ((i & 1) == 0) evenZeroes++; else oddZeroes++; }
        }
        var evenRatio = (double)evenZeroes / (length / 2);
        var oddRatio = (double)oddZeroes / (length / 2);
        if (oddRatio >= 0.35 && evenRatio <= 0.15) return true;
        if (evenRatio >= 0.35 && oddRatio <= 0.15) { bigEndian = true; return true; }
        return false;
    }

    private static bool TryDetectBomlessUtf32(ReadOnlySpan<byte> bytes, out bool bigEndian)
    {
        bigEndian = false;
        if (bytes.Length < 12) return false;
        var length = Math.Min(bytes.Length, 16 * 1024) & ~3;
        Span<int> zeroCounts = stackalloc int[4];
        var groups = length / 4;
        for (var i = 0; i < length; i++) if (bytes[i] == 0) zeroCounts[i & 3]++;
        Span<double> ratios = stackalloc double[4];
        for (var lane = 0; lane < 4; lane++) ratios[lane] = (double)zeroCounts[lane] / groups;
        if (ratios[1] >= 0.6 && ratios[2] >= 0.6 && ratios[3] >= 0.6 && ratios[0] <= 0.25) return true;
        if (ratios[0] >= 0.6 && ratios[1] >= 0.6 && ratios[2] >= 0.6 && ratios[3] <= 0.25) { bigEndian = true; return true; }
        return false;
    }

    private static async Task<byte[]> ReadSourceBytesAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > ILogParsingEngine.DefaultMaximumFileBytes)
            throw new InvalidDataException($"The selected file is {FormatBytes(stream.Length)}. Phase 1 supports files up to {FormatBytes(ILogParsingEngine.DefaultMaximumFileBytes)}.");

        using var buffer = new MemoryStream((int)stream.Length);
        var chunk = new byte[64 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (buffer.Length + read > ILogParsingEngine.DefaultMaximumFileBytes)
                throw new InvalidDataException($"The selected file grew beyond the {FormatBytes(ILogParsingEngine.DefaultMaximumFileBytes)} import limit while it was being read.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    private static LogDocumentFormat DetectFormat(string text, IReadOnlyList<string> sourceLines)
    {
        var trimmed = text.AsSpan().TrimStart();
        if (trimmed.StartsWith("{".AsSpan(), StringComparison.Ordinal) || trimmed.StartsWith("[".AsSpan(), StringComparison.Ordinal))
        {
            var nonEmpty = sourceLines.Where(line => !string.IsNullOrWhiteSpace(line)).Take(100).ToArray();
            if (nonEmpty.Length > 1 && nonEmpty.All(IsJsonValue)) return LogDocumentFormat.JsonLines;
            return LogDocumentFormat.Json;
        }
        if (trimmed.StartsWith("<".AsSpan(), StringComparison.Ordinal) &&
            (trimmed.StartsWith("<?xml".AsSpan(), StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("<Events".AsSpan(), StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("<Event".AsSpan(), StringComparison.OrdinalIgnoreCase)))
            return text.Contains("<Event", StringComparison.OrdinalIgnoreCase) && text.Contains("<EventID", StringComparison.OrdinalIgnoreCase)
                ? LogDocumentFormat.WindowsEventXml : LogDocumentFormat.Xml;
        var lines = sourceLines.Where(line => !string.IsNullOrWhiteSpace(line)).Take(20).ToArray();
        if (lines.Length >= 2 && lines.Count(IsSyslogLine) >= Math.Max(2, (lines.Length + 1) / 2)) return LogDocumentFormat.Syslog;
        if (lines.Length >= 2 && lines.Count(IsAccessLogLine) >= Math.Max(2, (lines.Length + 1) / 2)) return LogDocumentFormat.WebAccess;
        if (lines.Length >= 2 && TryParseCsvRow(lines[0], out var header) && TryParseCsvRow(lines[1], out var row) &&
            IsCredibleCsvHeader(header) && header.Count >= 2 && header.Count == row.Count)
            return LogDocumentFormat.Csv;
        if (lines.Any(line => IniSectionPattern.IsMatch(line)) && lines.Any(line => KeyValuePattern.IsMatch(line)))
            return LogDocumentFormat.Ini;
        if (lines.Length >= 2 && lines.Count(line => KeyValuePattern.Matches(line).Count >= 2) >= Math.Max(2, lines.Length / 2))
            return LogDocumentFormat.KeyValue;
        return LogDocumentFormat.PlainText;
    }

    private static bool IsCredibleCsvHeader(IReadOnlyList<string> headers)
    {
        if (headers.Count < 2 || headers.Any(string.IsNullOrWhiteSpace)) return false;
        var normalized = headers.Select(header => Regex.Replace(header.Trim(), @"[^A-Za-z0-9]", string.Empty)).ToArray();
        if (normalized.Any(header => TimestampPattern.IsMatch(header))) return false;
        var recognized = normalized.Count(CsvHeaderNames.Contains);
        return recognized >= 2 || recognized >= 1 && normalized.All(header => Regex.IsMatch(header, @"^[A-Za-z_][A-Za-z0-9_ .-]{0,63}$", RegexOptions.CultureInvariant));
    }

    private static bool IsSyslogLine(string line) => Syslog5424Pattern.IsMatch(line) || Syslog3164Pattern.IsMatch(line);
    private static bool IsAccessLogLine(string line) => AccessLogPattern.IsMatch(line);

    private static bool IsJsonValue(string line)
    {
        try { using var _ = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth }); return true; }
        catch (JsonException) { return false; }
    }

    private static List<ParsedLogEntry> ParseJsonLines(string[] lines, List<string> warnings)
    {
        var entries = new List<ParsedLogEntry>();
        var malformedLines = 0;
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            var line = lines[i]; if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var json = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth });
                entries.Add(CreateJsonEntry(entries.Count + 1, i + 1, i + 1, json.RootElement, line));
            }
            catch (JsonException ex)
            {
                malformedLines++;
                if (malformedLines <= MaximumDetailedWarnings)
                    warnings.Add($"Line {i + 1} is not valid JSON and was retained as plain text: {ex.Message}");
                entries.Add(CreateTextEntry(entries.Count + 1, i + 1, line));
            }
        }
        if (malformedLines > MaximumDetailedWarnings)
            warnings.Add($"{malformedLines - MaximumDetailedWarnings:N0} additional malformed JSON Lines were retained as plain text; detailed notes are capped to keep the review responsive.");
        return entries;
    }

    private static List<ParsedLogEntry> ParseJson(string text, string[] lines, List<string> warnings)
    {
        try
        {
            using var json = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth, CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            var entries = new List<ParsedLogEntry>();
            if (json.RootElement.ValueKind == JsonValueKind.Array)
            {
                var nextSourceLine = 1;
                foreach (var item in json.RootElement.EnumerateArray().Take(MaximumEntries))
                {
                    var raw = item.GetRawText();
                    var sourceLine = FindSourceLine(text, raw, nextSourceLine);
                    var sourceLineEnd = sourceLine + raw.Count(character => character == '\n');
                    entries.Add(CreateJsonEntry(entries.Count + 1, sourceLine, sourceLineEnd, item, raw));
                    nextSourceLine = sourceLineEnd + 1;
                }
            }
            else entries.Add(CreateJsonEntry(1, 1, lines.Length, json.RootElement, text.Trim()));
            if (json.RootElement.ValueKind == JsonValueKind.Array && json.RootElement.GetArrayLength() > MaximumEntries)
                warnings.Add($"Only the first {MaximumEntries:N0} JSON array records were parsed.");
            return entries;
        }
        catch (JsonException ex)
        {
            warnings.Add($"JSON parsing stopped ({ex.Message}); the complete original source is shown in raw-text mode.");
            return ParsePlainText(lines, warnings);
        }
    }

    private static List<ParsedLogEntry> ParseXml(string text, string[] sourceLines, List<string> warnings)
    {
        try
        {
            using var input = new StringReader(text);
            using var reader = XmlReader.Create(input, SafeXmlSettings());
            var xml = XDocument.Load(reader, LoadOptions.SetLineInfo);
            if (xml.Root is null) return new();
            var eventNodes = xml.Root.Name.LocalName.Equals("Event", StringComparison.OrdinalIgnoreCase)
                ? new[] { xml.Root }
                : xml.Descendants().Where(element => element.Name.LocalName.Equals("Event", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (eventNodes.Length > 0) return ParseWindowsEventXml(eventNodes, sourceLines);
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            FlattenXml(xml.Root, xml.Root.Name.LocalName, fields, 0);
            var message = GetField(fields, "message", "msg", "description", "text", "event");
            if (string.IsNullOrWhiteSpace(message)) message = xml.Root.Name.LocalName;
            var severity = ParseSeverity(GetField(fields, "level", "severity", "loglevel", "status"), message);
            var time = ParseTimestamp(GetField(fields, "timestamp", "time", "datetime", "created", "createdat"));
            var source = GetField(fields, "source", "provider", "logger", "component", "service", "application");
            var lineInfo = (IXmlLineInfo)xml.Root;
            return new() { new ParsedLogEntry(1, Math.Max(1, lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1), CountLines(text), time, severity, source, Limit(message), text, fields, "XML document fields; source line provenance points to the document root.") };
        }
        catch (XmlException ex)
        {
            warnings.Add($"XML parsing failed ({ex.Message}); the complete original source is shown in raw-text mode.");
            return ParsePlainText(sourceLines, warnings);
        }
    }

    private static List<ParsedLogEntry> ParseIni(string[] lines)
    {
        var sections = new List<IniSection>();
        IniSection? current = null;
        string? previousKey = null;
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var sectionMatch = IniSectionPattern.Match(line);
            if (sectionMatch.Success)
            {
                if (current is not null) sections.Add(current);
                current = new IniSection(sectionMatch.Groups["name"].Value.Trim(), i + 1);
                previousKey = null;
                current.RawLines.Add(line);
                continue;
            }
            if (current is null)
            {
                if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith(';') || line.TrimStart().StartsWith('#')) continue;
                current = new IniSection("DEFAULT", i + 1);
            }
            current.RawLines.Add(line);
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith(';') || line.TrimStart().StartsWith('#')) continue;
            var separator = line.IndexOf('=');
            if (separator <= 0) separator = line.IndexOf(':');
            if (separator > 0)
            {
                previousKey = line[..separator].Trim();
                if (current.Fields.Count < MaximumFieldsPerEntry)
                    current.Fields[previousKey] = Limit(Unquote(line[(separator + 1)..]));
            }
            else if (char.IsWhiteSpace(line[0]) && previousKey is not null)
                current.Fields[previousKey] = Limit(current.Fields[previousKey] + "\n" + line.Trim());
            else previousKey = null;
        }
        if (current is not null) sections.Add(current);

        return sections.Where(section => section.Fields.Count > 0).Take(MaximumEntries)
            .Select((section, index) => CreateFieldEntry(index + 1, section.StartLine,
                section.StartLine + section.RawLines.Count - 1, string.Join("\n", section.RawLines), section.Fields,
                $"INI section '{section.Name}' parsed as a record; key/value pairs were preserved.", section.Name))
            .ToList();
    }

    private static List<ParsedLogEntry> ParseKeyValue(string[] lines)
    {
        var entries = new List<ParsedLogEntry>();
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;
            var fields = ParseKeyValueFields(line);
            entries.Add(fields.Count < 2
                ? CreateTextEntry(entries.Count + 1, i + 1, line)
                : CreateFieldEntry(entries.Count + 1, i + 1, i + 1, line, fields,
                    "Logfmt-style key/value pairs were extracted from this record."));
        }
        return entries;
    }

    private static List<ParsedLogEntry> ParseSyslog(string[] lines, List<string> warnings)
    {
        var entries = new List<ParsedLogEntry>();
        var malformed = 0;
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;
            var match = Syslog5424Pattern.Match(line);
            var rfc5424 = match.Success;
            if (!match.Success) match = Syslog3164Pattern.Match(line);
            if (!match.Success)
            {
                malformed++;
                if (malformed <= MaximumDetailedWarnings) warnings.Add($"Line {i + 1} did not match RFC 5424 or RFC 3164 syslog and was retained as text.");
                entries.Add(CreateTextEntry(entries.Count + 1, i + 1, line));
                continue;
            }
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Host"] = match.Groups["host"].Value,
                ["Program"] = match.Groups["app"].Value
            };
            AddGroup(fields, "SyslogPriority", match, "priority");
            AddGroup(fields, "ProtocolVersion", match, "version");
            AddGroup(fields, "ProcessId", match, "procid");
            AddGroup(fields, "MessageId", match, "msgid");
            AddGroup(fields, "StructuredData", match, "structured");
            var timestamp = ParseSyslogTimestamp(match.Groups["timestamp"].Value, rfc5424, DateTimeOffset.Now.Year);
            if (timestamp is { } time) fields["Timestamp"] = time.ToString("O", CultureInfo.InvariantCulture);
            var message = match.Groups["message"].Value;
            var priority = int.TryParse(match.Groups["priority"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed <= 191 ? parsed : (int?)null;
            var prioritySeverity = priority is { } value ? ParseSyslogPriority(value) : LogEntrySeverity.Unknown;
            var messageSeverity = ParseSeverity(null, message);
            var severity = (int)messageSeverity > (int)prioritySeverity ? messageSeverity : prioritySeverity;
            if (severity == LogEntrySeverity.Unknown) severity = ParseSeverity(null, message);
            entries.Add(new ParsedLogEntry(entries.Count + 1, i + 1, i + 1, timestamp, severity,
                match.Groups["app"].Value, Limit(message), line, fields, rfc5424
                    ? "RFC 5424 priority, timestamp, host, application, process, message ID, structured data, and message were extracted."
                    : "RFC 3164 priority, local timestamp, host, application, process, and message were extracted; the current year is assumed."));
        }
        if (malformed > MaximumDetailedWarnings) warnings.Add($"{malformed - MaximumDetailedWarnings:N0} additional lines did not match a supported syslog header.");
        return entries;
    }

    private static List<ParsedLogEntry> ParseWebAccess(string[] lines, List<string> warnings)
    {
        var entries = new List<ParsedLogEntry>();
        var malformed = 0;
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;
            var match = AccessLogPattern.Match(line);
            if (!match.Success)
            {
                malformed++;
                if (malformed <= MaximumDetailedWarnings) warnings.Add($"Line {i + 1} did not match a supported combined access-log record and was retained as text.");
                entries.Add(CreateTextEntry(entries.Count + 1, i + 1, line));
                continue;
            }
            var requestParts = match.Groups["request"].Value.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            var status = match.Groups["status"].Value;
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ClientIp"] = match.Groups["client"].Value, ["Ident"] = match.Groups["ident"].Value,
                ["AuthenticatedUser"] = match.Groups["user"].Value, ["Request"] = match.Groups["request"].Value,
                ["StatusCode"] = status, ["ResponseBytes"] = match.Groups["bytes"].Value
            };
            if (requestParts.Length > 0) fields["Method"] = requestParts[0];
            if (requestParts.Length > 1) fields["Path"] = requestParts[1];
            if (requestParts.Length > 2) fields["Protocol"] = requestParts[2];
            AddGroup(fields, "Referrer", match, "referer");
            AddGroup(fields, "UserAgent", match, "agent");
            var timestamp = ParseAccessTimestamp(match.Groups["timestamp"].Value);
            if (timestamp is { } time) fields["Timestamp"] = time.ToString("O", CultureInfo.InvariantCulture);
            var message = $"HTTP {status} {match.Groups["request"].Value} from {match.Groups["client"].Value}";
            entries.Add(new ParsedLogEntry(entries.Count + 1, i + 1, i + 1, timestamp, ParseSeverity(status, message),
                match.Groups["client"].Value, Limit(message), line, fields,
                "Combined web access-log fields were decoded, including client, request, status, size, referrer, and user agent."));
        }
        if (malformed > MaximumDetailedWarnings) warnings.Add($"{malformed - MaximumDetailedWarnings:N0} additional lines did not match a supported combined access-log record.");
        return entries;
    }

    private static List<ParsedLogEntry> ParseWindowsEventXml(IReadOnlyList<XElement> eventNodes, IReadOnlyList<string> sourceLines)
    {
        var entries = new List<ParsedLogEntry>();
        foreach (var eventNode in eventNodes.Take(MaximumEntries))
        {
            var system = eventNode.Elements().FirstOrDefault(element => element.Name.LocalName == "System");
            var provider = system?.Elements().FirstOrDefault(element => element.Name.LocalName == "Provider");
            var eventId = system?.Elements().FirstOrDefault(element => element.Name.LocalName == "EventID")?.Value.Trim();
            var level = system?.Elements().FirstOrDefault(element => element.Name.LocalName == "Level")?.Value.Trim();
            var timeElement = system?.Elements().FirstOrDefault(element => element.Name.LocalName == "TimeCreated");
            var timestampText = timeElement?.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "SystemTime")?.Value;
            var computer = system?.Elements().FirstOrDefault(element => element.Name.LocalName == "Computer")?.Value.Trim();
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            AddIfValue(fields, "Provider", provider?.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Name")?.Value);
            AddIfValue(fields, "EventId", eventId);
            AddIfValue(fields, "Level", level);
            AddIfValue(fields, "Computer", computer);
            AddIfValue(fields, "Timestamp", timestampText);
            var valueIndex = 0;
            foreach (var data in eventNode.Descendants().Where(element => element.Name.LocalName == "Data").Take(MaximumFieldsPerEntry))
            {
                var name = data.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Name")?.Value;
                if (string.IsNullOrWhiteSpace(name)) name = $"Data{++valueIndex}";
                fields[name] = Limit(data.Value.Trim());
            }
            foreach (var child in eventNode.Descendants().Where(element => element.Name.LocalName is "Binary" or "UserData").Take(32))
                if (!fields.ContainsKey(child.Name.LocalName)) fields[child.Name.LocalName] = Limit(child.Value.Trim());

            var message = GetField(fields, "message", "msg", "description", "text", "details", "event");
            if (string.IsNullOrWhiteSpace(message))
                message = $"Windows event {eventId ?? "(unknown ID)"} from {fields.GetValueOrDefault("Provider", computer ?? "unknown provider")}";
            var timestamp = ParseTimestamp(timestampText);
            var severity = ParseWindowsEventLevel(level, message);
            var startLine = eventNode is IXmlLineInfo startInfo && startInfo.HasLineInfo() ? Math.Max(1, startInfo.LineNumber) : 1;
            var endLine = eventNode.DescendantNodesAndSelf().OfType<IXmlLineInfo>().Where(info => info.HasLineInfo()).Select(info => info.LineNumber).DefaultIfEmpty(startLine).Max();
            var raw = string.Join("\n", sourceLines.Skip(startLine - 1).Take(Math.Max(1, endLine - startLine + 1)));
            entries.Add(new ParsedLogEntry(entries.Count + 1, startLine, endLine, timestamp, severity,
                fields.GetValueOrDefault("Provider") ?? computer, Limit(message), raw, fields,
                "Windows Event XML system metadata and named EventData values were extracted; event boundaries are preserved."));
        }
        return entries;
    }

    private static ParsedLogEntry CreateFieldEntry(int index, int line, int lineEnd, string raw,
        Dictionary<string, string> fields, string interpretation, string? sectionName = null)
    {
        if (sectionName is not null) fields["Section"] = sectionName;
        var message = GetField(fields, "message", "msg", "description", "event", "text", "details", "action", "operation");
        if (string.IsNullOrWhiteSpace(message))
            message = string.Join("; ", fields.Where(pair => !IsMetadataField(pair.Key)).Take(8).Select(pair => $"{pair.Key}={pair.Value}"));
        var severity = ParseSeverity(GetField(fields, "severity", "level", "loglevel", "status", "statuscode"), message);
        var timestamp = ParseTimestamp(GetField(fields, "timestamp", "time", "datetime", "date", "ts", "@timestamp"));
        var source = GetField(fields, "source", "provider", "logger", "component", "service", "application", "host", "program");
        return new ParsedLogEntry(index, line, Math.Max(line, lineEnd), timestamp, severity, source, Limit(message), raw, fields, interpretation);
    }

    private static Dictionary<string, string> ParseKeyValueFields(string line)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in KeyValuePattern.Matches(line).Take(MaximumFieldsPerEntry))
            fields[match.Groups["key"].Value] = Limit(Unquote(match.Groups["value"].Value));
        return fields;
    }

    private static string Unquote(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && ((trimmed[0] == '"' && trimmed[^1] == '"') || (trimmed[0] == '\'' && trimmed[^1] == '\'')))
            return Regex.Unescape(trimmed[1..^1]);
        return trimmed;
    }

    private static void AddGroup(IDictionary<string, string> fields, string name, Match match, string groupName)
    {
        if (match.Groups[groupName].Success && !string.IsNullOrWhiteSpace(match.Groups[groupName].Value) && match.Groups[groupName].Value != "-")
            fields[name] = Limit(match.Groups[groupName].Value);
    }

    private static void AddIfValue(IDictionary<string, string> fields, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) fields[key] = Limit(value.Trim());
    }

    private static bool IsMetadataField(string key) =>
        key.Equals("timestamp", StringComparison.OrdinalIgnoreCase) || key.Equals("time", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("datetime", StringComparison.OrdinalIgnoreCase) || key.Equals("date", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("ts", StringComparison.OrdinalIgnoreCase) || key.Equals("level", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("severity", StringComparison.OrdinalIgnoreCase) || key.Equals("loglevel", StringComparison.OrdinalIgnoreCase);

    private static DateTimeOffset? ParseSyslogTimestamp(string value, bool rfc5424, int referenceYear)
    {
        if (value == "-" || string.IsNullOrWhiteSpace(value)) return null;
        if (rfc5424) return ParseTimestamp(value);
        if (!DateTime.TryParseExact(value, ["MMM d HH:mm:ss", "MMM  d HH:mm:ss"],
                CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.None, out var parsed)) return null;
        var local = new DateTime(referenceYear, parsed.Month, parsed.Day, parsed.Hour, parsed.Minute, parsed.Second, DateTimeKind.Unspecified);
        var timestamp = new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local));
        return timestamp > DateTimeOffset.Now.AddDays(1) ? timestamp.AddYears(-1) : timestamp;
    }

    private static DateTimeOffset? ParseAccessTimestamp(string value)
    {
        var offsetMatch = Regex.Match(value, @"(?<hour>[+-]\d{2})(?<minute>\d{2})$");
        if (offsetMatch.Success) value = value[..offsetMatch.Index] + offsetMatch.Groups["hour"].Value + ":" + offsetMatch.Groups["minute"].Value;
        return DateTimeOffset.TryParseExact(value, "dd/MMM/yyyy:HH:mm:ss zzz",
            CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.None, out var parsed) ? parsed : null;
    }

    private static LogEntrySeverity ParseSyslogPriority(int priority) => (priority % 8) switch
    {
        0 or 1 or 2 => LogEntrySeverity.Critical,
        3 => LogEntrySeverity.Error,
        4 => LogEntrySeverity.Warning,
        5 => LogEntrySeverity.Information,
        6 or 7 => LogEntrySeverity.Debug,
        _ => LogEntrySeverity.Unknown
    };

    private static LogEntrySeverity ParseWindowsEventLevel(string? level, string message) => level switch
    {
        "1" => LogEntrySeverity.Critical,
        "2" => LogEntrySeverity.Error,
        "3" => LogEntrySeverity.Warning,
        "4" => LogEntrySeverity.Information,
        "5" => LogEntrySeverity.Debug,
        _ => ParseSeverity(null, message)
    };

    private sealed class IniSection(string name, int startLine)
    {
        public string Name { get; } = name;
        public int StartLine { get; } = startLine;
        public Dictionary<string, string> Fields { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> RawLines { get; } = [];
    }

    private static List<ParsedLogEntry> ParseCsv(string[] lines, List<string> warnings)
    {
        var nonEmptyIndices = Enumerable.Range(0, lines.Length).Where(i => !string.IsNullOrWhiteSpace(lines[i])).ToArray();
        if (nonEmptyIndices.Length == 0 || !TryParseCsvRow(lines[nonEmptyIndices[0]], out var headers)) return ParsePlainText(lines, warnings);
        var entries = new List<ParsedLogEntry>();
        var malformedRows = 0;
        foreach (var lineIndex in nonEmptyIndices.Skip(1).Take(MaximumEntries))
        {
            if (!TryParseCsvRow(lines[lineIndex], out var values) || values.Count != headers.Count)
            {
                malformedRows++;
                if (malformedRows <= MaximumDetailedWarnings)
                    warnings.Add($"CSV line {lineIndex + 1} has an unmatched quote or a different number of columns; it is retained as plain text.");
                entries.Add(CreateTextEntry(entries.Count + 1, lineIndex + 1, lines[lineIndex]));
                continue;
            }
            var fields = headers.Select((header, index) => (Key: string.IsNullOrWhiteSpace(header) ? $"Column{index + 1}" : header.Trim(), Value: Limit(values[index])))
                .GroupBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.OrdinalIgnoreCase);
            var message = GetField(fields, "message", "msg", "description", "event", "text", "details") ?? string.Join(" · ", values);
            var time = ParseTimestamp(GetField(fields, "timestamp", "time", "datetime", "date", "created"));
            var severity = ParseSeverity(GetField(fields, "level", "severity", "loglevel", "status"), message);
            var source = GetField(fields, "source", "provider", "logger", "component", "service", "application");
            entries.Add(new ParsedLogEntry(entries.Count + 1, lineIndex + 1, lineIndex + 1, time, severity, source, Limit(message), lines[lineIndex], fields, "CSV columns mapped by the header row."));
        }
        if (malformedRows > MaximumDetailedWarnings)
            warnings.Add($"{malformedRows - MaximumDetailedWarnings:N0} additional malformed CSV rows were retained as plain text; detailed notes are capped to keep the review responsive.");
        return entries;
    }

    private static List<ParsedLogEntry> ParsePlainText(string[] lines, List<string>? warnings = null)
    {
        var entries = new List<ParsedLogEntry>();
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i])) continue;
            try
            {
                if (entries.Count > 0 && IsExceptionContinuation(lines[i]))
                {
                    var previous = entries[^1];
                    var details = previous.Fields.TryGetValue("ExceptionDetails", out var existing) ? existing + "\n" : string.Empty;
                    var fields = previous.Fields.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
                    fields["ExceptionDetails"] = Limit(details + lines[i].Trim());
                    entries[^1] = previous with
                    {
                        SourceLineEnd = i + 1,
                        Message = Limit(previous.Message + "\n" + lines[i].Trim()),
                        RawText = previous.RawText + "\n" + lines[i],
                        Fields = fields,
                        InterpretationBasis = previous.InterpretationBasis + " Indented exception/traceback continuation lines were attached to their preceding event."
                    };
                    continue;
                }
                entries.Add(CreateTextEntry(entries.Count + 1, i + 1, lines[i]));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                if (warnings is not null && warnings.Count < MaximumDetailedWarnings)
                    warnings.Add($"Line {i + 1} could not be analyzed ({ex.GetType().Name}: {ex.Message}); it was retained as raw text.");
                entries.Add(CreateRawEntry(entries.Count + 1, i + 1, lines[i], ex));
            }
        }
        return entries;
    }

    private static ParsedLogEntry CreateRawEntry(int index, int line, string raw, Exception? error = null) =>
        new(index, line, line, null, LogEntrySeverity.Unknown, null, Limit(raw.Trim()), raw,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            error is null ? "Raw source retained without field interpretation." : $"Line analysis failed with {error.GetType().Name}; raw source was retained.");

    private static bool IsExceptionContinuation(string line)
    {
        var trimmed = line.TrimStart();
        return char.IsWhiteSpace(line[0]) ||
            trimmed.StartsWith("Traceback (most recent call last)", StringComparison.OrdinalIgnoreCase) ||
            Regex.IsMatch(trimmed, @"^File ""[^""]+"", line \d+", RegexOptions.CultureInvariant, PatternTimeout) ||
            Regex.IsMatch(trimmed, @"^[A-Za-z_][A-Za-z0-9_.]*Error:", RegexOptions.CultureInvariant, PatternTimeout) ||
            trimmed.StartsWith("Caused by:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("Inner exception:", StringComparison.OrdinalIgnoreCase) ||
            Regex.IsMatch(trimmed, @"^(?:[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Fault))(?::|\s|$)", RegexOptions.CultureInvariant, PatternTimeout);
    }

    private static ParsedLogEntry CreateTextEntry(int index, int line, string text)
    {
        var fields = ParseKeyValueFields(text);
        var timestampMatch = TimestampPattern.Match(text);
        DateTimeOffset? timestamp = ParseTimestamp(GetField(fields, "timestamp", "time", "datetime", "date", "ts", "@timestamp"));
        if (timestamp is null && timestampMatch.Success) timestamp = ParseTimestamp(timestampMatch.Value.Replace(',', '.'));
        var severityMatch = SeverityPattern.Match(text);
        var severity = ParseSeverity(GetField(fields, "level", "severity", "loglevel", "status", "statuscode"), text);
            if (severityMatch.Success)
            {
                var messageSeverity = ParseSeverity(severityMatch.Value, text);
                if ((int)messageSeverity > (int)severity) severity = messageSeverity;
            }
        if (timestamp is not null) fields["Timestamp"] = timestamp.Value.ToString("O", CultureInfo.InvariantCulture);
        if (severity != LogEntrySeverity.Unknown) fields["Severity"] = severity.ToString();
        var code = ErrorCodePattern.Match(text);
        if (code.Success) { fields["Code"] = code.Value; fields.TryAdd("ErrorCode", code.Value); }
        var sourceMatch = Regex.Match(text, @"\[([^\]]{1,120})\]", RegexOptions.CultureInvariant);
        var source = GetField(fields, "source", "provider", "logger", "component", "service", "application", "host", "program") ??
            (sourceMatch.Success ? sourceMatch.Groups[1].Value : null);
        if (source is not null) fields["Source"] = source;
        return new ParsedLogEntry(index, line, line, timestamp, severity, source, Limit(text.Trim()), text,
            fields, fields.Count == 0 ? "Plain-text line retained; no recognized timestamp, severity, or code pattern matched." : "Best-effort timestamp, severity, source, or code pattern matched in the source line.");
    }

    private static ParsedLogEntry CreateJsonEntry(int index, int line, int lineEnd, JsonElement element, string raw)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        FlattenJson(element, "", fields, 0);
        var message = GetField(fields, "message", "msg", "description", "event", "text", "details", "exception.message") ??
            (element.ValueKind == JsonValueKind.String ? element.GetString() : null) ?? raw.Trim();
        var severityText = GetField(fields, "level", "severity", "loglevel", "status", "type");
        var severity = ParseSeverity(severityText, message);
        var timestamp = ParseTimestamp(GetField(fields, "timestamp", "time", "datetime", "date", "created", "createdat", "@timestamp"));
        var source = GetField(fields, "source", "provider", "logger", "component", "service", "application", "name");
        return new ParsedLogEntry(index, Math.Max(1, line), Math.Max(line, lineEnd), timestamp, severity, source,
            Limit(message), raw, fields, "JSON property names and scalar values extracted; source lines are approximate for nested documents.");
    }

    private static void FlattenJson(JsonElement element, string path, IDictionary<string, string> fields, int depth)
    {
        if (depth > 16 || fields.Count >= MaximumFieldsPerEntry) return;
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject()) FlattenJson(property.Value, string.IsNullOrEmpty(path) ? property.Name : $"{path}.{property.Name}", fields, depth + 1);
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray().Take(64)) FlattenJson(item, $"{path}[{index++}]", fields, depth + 1);
        }
        else
        {
            var value = element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                JsonValueKind.Null or JsonValueKind.Undefined => null,
                _ => element.GetRawText()
            };
            if (!string.IsNullOrEmpty(path) && value is not null) fields[path] = Limit(value);
        }
    }

    private static void FlattenXml(XElement element, string path, IDictionary<string, string> fields, int depth)
    {
        if (depth > 16 || fields.Count >= MaximumFieldsPerEntry) return;
        foreach (var attribute in element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration).Take(64))
            fields[$"{path}.@{attribute.Name.LocalName}"] = Limit(attribute.Value.Trim());
        var children = element.Elements().ToArray();
        if (children.Length == 0)
        {
            if (!string.IsNullOrWhiteSpace(element.Value)) fields[path] = Limit(element.Value.Trim());
            return;
        }
        foreach (var child in children.Take(MaximumFieldsPerEntry)) FlattenXml(child, $"{path}.{child.Name.LocalName}", fields, depth + 1);
    }

    private static bool TryParseCsvRow(string line, out List<string> values)
    {
        values = new List<string>(); var field = new StringBuilder(); var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (quoted)
            {
                if (ch == '"' && i + 1 < line.Length && line[i + 1] == '"') { field.Append('"'); i++; }
                else if (ch == '"') quoted = false;
                else field.Append(ch);
            }
            else if (ch == ',') { values.Add(field.ToString()); field.Clear(); }
            else if (ch == '"' && field.Length == 0) quoted = true;
            else field.Append(ch);
        }
        if (quoted) return false;
        values.Add(field.ToString());
        return true;
    }

    private static LogEntrySeverity ParseSeverity(string? explicitValue, string? message)
    {
        var value = explicitValue?.Trim().ToLowerInvariant();
        if (value is not null)
        {
            if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var httpStatus) && httpStatus is >= 500 and <= 599) return LogEntrySeverity.Error;
            if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out httpStatus) && httpStatus is >= 400 and <= 499) return LogEntrySeverity.Warning;
            if (value.Contains("critical") || value.Contains("fatal") || value.Contains("panic") || value.Contains("emergency")) return LogEntrySeverity.Critical;
            if (value.Contains("error") || value is "err" or "failed" or "failure" or "exception" or "crash" or "crit" or "alert" or "emerg") return LogEntrySeverity.Error;
            if (value.Contains("warn")) return LogEntrySeverity.Warning;
            if (value.Contains("success") || value is "succeeded" or "completed") return LogEntrySeverity.Success;
            if (value.Contains("info") || value is "notice" or "normal") return LogEntrySeverity.Information;
            if (value.Contains("debug")) return LogEntrySeverity.Debug;
            if (value.Contains("trace") || value.Contains("verbose")) return LogEntrySeverity.Trace;
        }
        if (!string.IsNullOrWhiteSpace(message))
        {
            var match = SeverityPattern.Match(message);
            if (match.Success) return ParseSeverity(match.Value, null);
        }
        return LogEntrySeverity.Unknown;
    }

    private static DateTimeOffset? ParseTimestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return DateTimeOffset.TryParse(value.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed) ? parsed : null;
    }

    private static string? GetField(IReadOnlyDictionary<string, string> fields, params string[] candidates)
    {
        foreach (var candidate in candidates)
        {
            foreach (var (key, value) in fields)
            {
                var name = key.Split('.').LastOrDefault()?.TrimStart('@');
                if ((key.Equals(candidate, StringComparison.OrdinalIgnoreCase) || string.Equals(name, candidate, StringComparison.OrdinalIgnoreCase)) && !string.IsNullOrWhiteSpace(value)) return value;
            }
        }
        return null;
    }

    private static int FindSourceLine(string text, string snippet, int afterLine = 1)
    {
        if (string.IsNullOrEmpty(snippet)) return afterLine;
        var searchStart = 0;
        for (var line = 1; line < afterLine && searchStart < text.Length; line++)
        {
            var newline = text.IndexOf('\n', searchStart);
            if (newline < 0) return afterLine;
            searchStart = newline + 1;
        }
        var index = text.IndexOf(snippet, searchStart, StringComparison.Ordinal);
        if (index < 0) return afterLine;
        var sourceLine = 1;
        for (var i = 0; i < index; i++) if (text[i] == '\n') sourceLine++;
        return sourceLine;
    }

    private static int CountLines(string text) => 1 + text.Count(character => character == '\n');
    private static string Limit(string value) => value.Length <= MaximumFieldValueLength ? value : value[..MaximumFieldValueLength] + "… [truncated]";
    private static string FormatBytes(long bytes) => bytes >= 1024 * 1024 ? $"{bytes / (1024d * 1024d):0.#} MB" : $"{bytes / 1024d:0.#} KB";
    private static XmlReaderSettings SafeXmlSettings() => new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = ILogParsingEngine.DefaultMaximumFileBytes, IgnoreComments = false };
}
