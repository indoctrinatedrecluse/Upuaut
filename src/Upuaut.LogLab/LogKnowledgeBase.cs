using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>Loads the shipped, offline knowledge set. Malformed or absent embedded data disables these patterns without blocking parsing.</summary>
public static class LogKnowledgeBase
{
    private const string ResourceName = "Upuaut.LogLab.Knowledge.log-knowledge-base.json";
    private const int MaximumDatasetBytes = 1_000_000;
    private static readonly Lazy<IReadOnlyList<LogKnowledgePattern>> BuiltIn = new(LoadBuiltIn, LazyThreadSafetyMode.ExecutionAndPublication);

    public static IReadOnlyList<LogKnowledgePattern> GetBuiltInPatterns() => BuiltIn.Value;

    private static IReadOnlyList<LogKnowledgePattern> LoadBuiltIn()
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName);
            if (stream is null || stream.Length is <= 0 or > MaximumDatasetBytes) return [];
            using var reader = new StreamReader(stream);
            var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
            options.Converters.Add(new JsonStringEnumConverter());
            var patterns = JsonSerializer.Deserialize<LogKnowledgePattern[]>(reader.ReadToEnd(), options) ?? [];
            return patterns.Where(pattern => pattern is not null && IsValid(pattern)).Take(512).ToArray();
        }
        catch (Exception)
        {
            return [];
        }
    }

    private static bool IsValid(LogKnowledgePattern pattern) =>
        !string.IsNullOrWhiteSpace(pattern.Id) && pattern.Id.Length <= 96 &&
        !string.IsNullOrWhiteSpace(pattern.Headline) && pattern.Headline.Length <= 180 &&
        !string.IsNullOrWhiteSpace(pattern.Explanation) && pattern.Explanation.Length <= 1200 &&
        pattern.Signals is { Count: > 0 and <= 16 } && pattern.Signals.All(signal => !string.IsNullOrWhiteSpace(signal) && signal.Length <= 180) &&
        pattern.Tags is { Count: <= 12 } && pattern.Recommendations is { Count: > 0 and <= 8 } &&
        Uri.TryCreate(pattern.SourceUrl, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        Enum.IsDefined(pattern.Category) && !string.IsNullOrWhiteSpace(pattern.SourceName) && !string.IsNullOrWhiteSpace(pattern.Example);
}
