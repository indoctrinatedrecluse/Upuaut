using System.Globalization;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>Validates, persists, and applies bounded user-authored regex parsing profiles.</summary>
public sealed class LogParserProfileService : ILogParserProfileService
{
    private const int MaximumProfiles = 30;
    private const int MaximumFieldRules = 32;
    private const int MaximumPatternLength = 512;
    private const int MaximumEntries = 200_000;
    private static readonly TimeSpan MaximumApplyDuration = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true, MaxDepth = 16 };

    private string ProfileFilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Upuaut", "log-parser-profiles.json");

    public IReadOnlyList<LogParserProfile> LoadProfiles()
    {
        var path = ProfileFilePath;
        if (!File.Exists(path)) return [];
        try
        {
            var profiles = JsonSerializer.Deserialize<List<LogParserProfile>>(File.ReadAllText(path), JsonOptions) ?? [];
            return profiles.Take(MaximumProfiles).Select(Validate).ToArray();
        }
        catch (Exception ex) when (ex is IOException or JsonException or ArgumentException or RegexMatchTimeoutException)
        {
            throw new InvalidDataException($"Saved parser profiles could not be loaded: {ex.Message}", ex);
        }
    }

    public IReadOnlyList<LogParserProfile> GetBuiltInProfiles() => BuiltInLogParserProfiles.All;

    public LogParserProfile ParseAndValidate(string json)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > 64 * 1024) throw new InvalidDataException("Profile JSON must be present and no larger than 64 KiB.");
        var profile = JsonSerializer.Deserialize<LogParserProfile>(json, JsonOptions) ?? throw new InvalidDataException("The profile JSON is empty.");
        return Validate(profile);
    }

    public string Serialize(LogParserProfile profile) => JsonSerializer.Serialize(Validate(profile), JsonOptions);

    public void SaveProfile(LogParserProfile profile)
    {
        profile = Validate(profile);
        var profiles = LoadProfiles().Where(item => !item.Name.Equals(profile.Name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (profiles.Count >= MaximumProfiles) throw new InvalidOperationException($"You can save up to {MaximumProfiles} parser profiles.");
        profiles.Add(profile);
        var path = ProfileFilePath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(profiles, JsonOptions));
        File.Move(temp, path, overwrite: true);
    }

    public void DeleteProfile(string name)
    {
        var path = ProfileFilePath;
        if (!File.Exists(path)) return;
        var profiles = LoadProfiles().Where(item => !item.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray();
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(profiles, JsonOptions));
        File.Move(temp, path, overwrite: true);
    }

    public LogProfileApplyResult Apply(LogDocument document, LogParserProfile profile)
    {
        ArgumentNullException.ThrowIfNull(document);
        profile = Validate(profile);
        var lineRegex = Compile(profile.LinePattern);
        var fieldRegexes = profile.Fields.Select(field => (Field: field, Regex: Compile(field.Pattern))).ToArray();
        var entries = new List<ParsedLogEntry>();
        var warnings = document.Warnings.ToList();
        var elapsed = Stopwatch.StartNew();
        foreach (var (line, offset) in document.SourceLines.Select((value, index) => (value, index)).Take(MaximumEntries))
        {
            if (elapsed.Elapsed > MaximumApplyDuration) { warnings.Add($"Profile processing reached the {MaximumApplyDuration.TotalSeconds:0}-second work limit and stopped at source line {offset + 1}."); break; }
            if (string.IsNullOrWhiteSpace(line)) continue;
            Match lineMatch;
            try { lineMatch = lineRegex.Match(line); }
            catch (RegexMatchTimeoutException) { warnings.Add($"Profile '{profile.Name}' timed out while checking line {offset + 1}; remaining lines were skipped."); break; }
            if (!lineMatch.Success) continue;

            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ParserProfile"] = profile.Name };
            var profileTimedOut = false;
            foreach (var (field, regex) in fieldRegexes)
            {
                try
                {
                    var match = regex.Match(line);
                    if (!match.Success) continue;
                    var group = match.Groups[field.GroupName];
                    if (group.Success) fields[field.Name] = Limit(group.Value.Trim());
                }
                catch (RegexMatchTimeoutException) { warnings.Add($"A field pattern timed out on line {offset + 1}; profile processing stopped safely."); profileTimedOut = true; break; }
            }

            var message = GetField(fields, "message", "msg", "description", "event", "text") ?? line.Trim();
            var timestamp = DateTimeOffset.TryParse(GetField(fields, "timestamp", "time", "datetime", "date"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsedTime) ? parsedTime : (DateTimeOffset?)null;
            var severity = ParseSeverity(GetField(fields, "severity", "level", "loglevel", "status"));
            if (severity == LogEntrySeverity.Unknown && int.TryParse(GetField(fields, "syslogpriority"), NumberStyles.None, CultureInfo.InvariantCulture, out var priority) && priority <= 191)
                severity = ((priority % 8) switch { 0 => LogEntrySeverity.Critical, 1 => LogEntrySeverity.Critical, 2 => LogEntrySeverity.Critical, 3 => LogEntrySeverity.Error, 4 => LogEntrySeverity.Warning, 5 => LogEntrySeverity.Information, 6 => LogEntrySeverity.Information, _ => LogEntrySeverity.Debug });
            var source = GetField(fields, "source", "provider", "logger", "component", "service", "application");
            entries.Add(new ParsedLogEntry(entries.Count + 1, offset + 1, offset + 1, timestamp, severity, source, message, line, fields,
                $"Custom profile '{profile.Name}' matched the source line; configured field patterns extracted the displayed fields."));
            if (profileTimedOut) break;
        }

        if (entries.Count == 0) throw new InvalidDataException($"Profile '{profile.Name}' did not match any source lines.");
        if (document.SourceLines.Count > MaximumEntries) warnings.Add($"Custom profile processing was bounded to the first {MaximumEntries:N0} source lines.");
        warnings.Add($"Custom profile '{profile.Name}' matched {entries.Count:N0} of {Math.Min(document.SourceLines.Count, MaximumEntries):N0} processed source lines.");
        var profiled = document with { Format = LogDocumentFormat.CustomProfile, ImportedAtUtc = DateTimeOffset.UtcNow, Entries = entries, Warnings = warnings };
        return new LogProfileApplyResult(profiled, entries.Count, Math.Min(document.SourceLines.Count, MaximumEntries));
    }

    private static LogParserProfile Validate(LogParserProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Name) || profile.Name.Trim().Length > 80) throw new InvalidDataException("Profile name is required and must be 80 characters or fewer.");
        if (profile.Description?.Length > 500) throw new InvalidDataException("Profile description must be 500 characters or fewer.");
        if (profile.Fields is null || profile.Fields.Count == 0 || profile.Fields.Count > MaximumFieldRules) throw new InvalidDataException($"A profile must define between 1 and {MaximumFieldRules} field patterns.");
        _ = Compile(profile.LinePattern, compiled: false);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in profile.Fields)
        {
            if (string.IsNullOrWhiteSpace(field.Name) || field.Name.Length > 80 || !names.Add(field.Name)) throw new InvalidDataException("Field names must be unique, non-empty, and 80 characters or fewer.");
            var regex = Compile(field.Pattern, compiled: false);
            if (string.IsNullOrWhiteSpace(field.GroupName) || field.GroupName.Length > 80) throw new InvalidDataException($"The capture group for '{field.Name}' is invalid.");
            if (!regex.GetGroupNames().Contains(field.GroupName, StringComparer.Ordinal)) throw new InvalidDataException($"The pattern for '{field.Name}' does not define capture group '{field.GroupName}'.");
        }
        return profile with { Name = profile.Name.Trim(), Description = profile.Description?.Trim() ?? string.Empty };
    }

    private static Regex Compile(string pattern, bool compiled = true)
    {
        if (string.IsNullOrWhiteSpace(pattern) || pattern.Length > MaximumPatternLength) throw new InvalidDataException($"Regex patterns must be non-empty and no longer than {MaximumPatternLength} characters.");
        try { return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | (compiled ? RegexOptions.Compiled : RegexOptions.None), RegexTimeout); }
        catch (ArgumentException ex) { throw new InvalidDataException($"A profile contains an invalid regex: {ex.Message}", ex); }
    }

    private static string? GetField(IReadOnlyDictionary<string, string> fields, params string[] names) =>
        names.Select(name => fields.FirstOrDefault(pair => pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    private static LogEntrySeverity ParseSeverity(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "trace" or "verbose" => LogEntrySeverity.Trace,
        "debug" => LogEntrySeverity.Debug,
        "info" or "information" or "notice" => LogEntrySeverity.Information,
        "warn" or "warning" => LogEntrySeverity.Warning,
        "error" or "err" or "fail" or "failed" or "failure" or "exception" => LogEntrySeverity.Error,
        "fatal" or "critical" or "crit" or "emerg" or "alert" or "panic" => LogEntrySeverity.Critical,
        "success" or "succeeded" or "completed" => LogEntrySeverity.Success,
        var status when int.TryParse(status, NumberStyles.None, CultureInfo.InvariantCulture, out var serverCode) && serverCode is >= 500 and <= 599 => LogEntrySeverity.Error,
        var status when int.TryParse(status, NumberStyles.None, CultureInfo.InvariantCulture, out var clientCode) && clientCode is >= 400 and <= 499 => LogEntrySeverity.Warning,
        _ => LogEntrySeverity.Unknown
    };

    private static string Limit(string value) => value.Length <= 16_384 ? value : value[..16_384] + "... [truncated]";
}
