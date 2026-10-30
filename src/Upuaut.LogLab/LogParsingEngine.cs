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
    private const int MaximumFieldsPerEntry = 512;
    private const int MaximumFieldValueLength = 16_384;
    private const int MaximumJsonDepth = 64;
    private static readonly Regex TimestampPattern = new(@"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SeverityPattern = new(@"\b(trace|verbose|debug|info|information|notice|warn|warning|error|err|fatal|critical|success|succeeded|failed|failure|exception|crash)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex ErrorCodePattern = new(@"\b(?:0x[0-9a-f]{4,16}|(?:error|exception|status|code)[ _:=#-]*[A-Z]?[A-Z0-9_-]{2,})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public async Task<LogDocument> ImportFileAsync(string path, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Select a log file to import.", nameof(path));
        var fullPath = Path.GetFullPath(path);
        var info = new FileInfo(fullPath);
        if (!info.Exists) throw new FileNotFoundException("The selected log file was not found.", fullPath);
        if (info.Length == 0) throw new InvalidDataException("The selected file is empty.");
        if (info.Length > ILogParsingEngine.DefaultMaximumFileBytes)
            throw new InvalidDataException($"The selected file is {FormatBytes(info.Length)}. Phase 1 supports files up to {FormatBytes(ILogParsingEngine.DefaultMaximumFileBytes)}.");

        var bytes = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var (text, encodingName) = Decode(bytes);
        if (text.Contains('\0')) throw new InvalidDataException("The selected file contains binary data and cannot be imported as a text log.");

        var sourceLines = text.Split('\n').Select(line => line.EndsWith('\r') ? line[..^1] : line).ToArray();
        var warnings = new List<string>();
        var format = DetectFormat(text);
        var entries = format switch
        {
            LogDocumentFormat.JsonLines => ParseJsonLines(sourceLines, warnings),
            LogDocumentFormat.Json => ParseJson(text, sourceLines, warnings),
            LogDocumentFormat.Xml => ParseXml(text, warnings),
            LogDocumentFormat.Csv => ParseCsv(sourceLines, warnings),
            _ => ParsePlainText(sourceLines)
        };

        if (entries.Count == 0 && sourceLines.Any(line => !string.IsNullOrWhiteSpace(line)))
        {
            warnings.Add("The input was retained, but no structured entries could be extracted. Review the source text or try a custom parser profile in a future release.");
            entries = ParsePlainText(sourceLines);
            format = LogDocumentFormat.PlainText;
        }

        return new LogDocument(Path.GetFileName(fullPath), fullPath, bytes.LongLength, encodingName, format,
            DateTimeOffset.UtcNow, text, sourceLines, entries, warnings);
    }

    public IReadOnlyList<ParsedLogEntry> Search(LogDocument document, LogSearchOptions options)
    {
        ArgumentNullException.ThrowIfNull(document);
        var query = options.Query?.Trim();
        IEnumerable<ParsedLogEntry> entries = document.Entries;
        if (options.Severity is { } severity) entries = entries.Where(entry => entry.Severity == severity);
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
        if (bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) return (new UTF8Encoding(false, true).GetString(bytes, 3, bytes.Length - 3), "UTF-8 (BOM)");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE, 0x00, 0x00 })) return (new UTF32Encoding(false, true, true).GetString(bytes, 4, bytes.Length - 4), "UTF-32 LE");
        if (bytes.AsSpan().StartsWith(new byte[] { 0x00, 0x00, 0xFE, 0xFF })) return (new UTF32Encoding(true, true, true).GetString(bytes, 4, bytes.Length - 4), "UTF-32 BE");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE })) return (new UnicodeEncoding(false, false, true).GetString(bytes, 2, bytes.Length - 2), "UTF-16 LE");
        if (bytes.AsSpan().StartsWith(new byte[] { 0xFE, 0xFF })) return (new UnicodeEncoding(true, false, true).GetString(bytes, 2, bytes.Length - 2), "UTF-16 BE");
        try { return (new UTF8Encoding(false, true).GetString(bytes), "UTF-8"); }
        catch (DecoderFallbackException) { return (Encoding.Latin1.GetString(bytes), "ISO-8859-1 fallback"); }
    }

    private static LogDocumentFormat DetectFormat(string text)
    {
        var trimmed = text.AsSpan().TrimStart();
        if (trimmed.StartsWith("{".AsSpan(), StringComparison.Ordinal) || trimmed.StartsWith("[".AsSpan(), StringComparison.Ordinal))
        {
            var nonEmpty = text.Split('\n').Where(line => !string.IsNullOrWhiteSpace(line)).Take(100).ToArray();
            if (nonEmpty.Length > 1 && nonEmpty.All(IsJsonValue)) return LogDocumentFormat.JsonLines;
            return LogDocumentFormat.Json;
        }
        if (trimmed.StartsWith("<".AsSpan(), StringComparison.Ordinal)) return LogDocumentFormat.Xml;
        var lines = text.Split('\n').Select(line => line.TrimEnd('\r')).Where(line => !string.IsNullOrWhiteSpace(line)).Take(2).ToArray();
        if (lines.Length == 2 && TryParseCsvRow(lines[0], out var header) && TryParseCsvRow(lines[1], out var row) && header.Count >= 2 && header.Count == row.Count)
            return LogDocumentFormat.Csv;
        return LogDocumentFormat.PlainText;
    }

    private static bool IsJsonValue(string line)
    {
        try { using var _ = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth }); return true; }
        catch (JsonException) { return false; }
    }

    private static List<ParsedLogEntry> ParseJsonLines(string[] lines, List<string> warnings)
    {
        var entries = new List<ParsedLogEntry>();
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            var line = lines[i]; if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var json = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth });
                entries.Add(CreateJsonEntry(entries.Count + 1, i + 1, i + 1, json.RootElement, line));
            }
            catch (JsonException ex) { warnings.Add($"Line {i + 1} is not valid JSON and was retained as plain text: {ex.Message}"); entries.Add(CreateTextEntry(entries.Count + 1, i + 1, line)); }
        }
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
            warnings.Add($"JSON parsing stopped: {ex.Message}");
            return ParsePlainText(lines);
        }
    }

    private static List<ParsedLogEntry> ParseXml(string text, List<string> warnings)
    {
        try
        {
            using var input = new StringReader(text);
            using var reader = XmlReader.Create(input, SafeXmlSettings());
            var xml = XDocument.Load(reader, LoadOptions.SetLineInfo);
            if (xml.Root is null) return new();
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
            warnings.Add($"XML parsing failed; the original text is still available: {ex.Message}");
            return ParsePlainText(text.Split('\n').Select(line => line.TrimEnd('\r')).ToArray());
        }
    }

    private static List<ParsedLogEntry> ParseCsv(string[] lines, List<string> warnings)
    {
        var nonEmptyIndices = Enumerable.Range(0, lines.Length).Where(i => !string.IsNullOrWhiteSpace(lines[i])).ToArray();
        if (nonEmptyIndices.Length == 0 || !TryParseCsvRow(lines[nonEmptyIndices[0]], out var headers)) return ParsePlainText(lines);
        var entries = new List<ParsedLogEntry>();
        foreach (var lineIndex in nonEmptyIndices.Skip(1).Take(MaximumEntries))
        {
            if (!TryParseCsvRow(lines[lineIndex], out var values) || values.Count != headers.Count)
            {
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
        return entries;
    }

    private static List<ParsedLogEntry> ParsePlainText(string[] lines)
    {
        var entries = new List<ParsedLogEntry>();
        for (var i = 0; i < lines.Length && entries.Count < MaximumEntries; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i])) continue;
            entries.Add(CreateTextEntry(entries.Count + 1, i + 1, lines[i]));
        }
        return entries;
    }

    private static ParsedLogEntry CreateTextEntry(int index, int line, string text)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var timestampMatch = TimestampPattern.Match(text);
        DateTimeOffset? timestamp = timestampMatch.Success ? ParseTimestamp(timestampMatch.Value) : null;
        var severityMatch = SeverityPattern.Match(text);
        var severity = severityMatch.Success ? ParseSeverity(severityMatch.Value, text) : LogEntrySeverity.Unknown;
        if (timestamp is not null) fields["Timestamp"] = timestamp.Value.ToString("O", CultureInfo.InvariantCulture);
        if (severity != LogEntrySeverity.Unknown) fields["Severity"] = severity.ToString();
        var code = ErrorCodePattern.Match(text);
        if (code.Success) fields["Code"] = code.Value;
        var sourceMatch = Regex.Match(text, @"\[([^\]]{1,120})\]", RegexOptions.CultureInvariant);
        var source = sourceMatch.Success ? sourceMatch.Groups[1].Value : null;
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
            if (value.Contains("critical") || value.Contains("fatal") || value.Contains("panic") || value.Contains("emergency")) return LogEntrySeverity.Critical;
            if (value.Contains("error") || value is "err" or "failed" or "failure" or "exception" or "crash") return LogEntrySeverity.Error;
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
