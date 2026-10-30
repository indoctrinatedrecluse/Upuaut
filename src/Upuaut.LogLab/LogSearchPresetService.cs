using System.Text.Json;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public sealed class LogSearchPresetService : ILogSearchPresetService
{
    private const int MaximumPresets = 50;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    private static string PresetFilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Upuaut", "log-search-presets.json");

    public IReadOnlyList<LogSearchPreset> Load()
    {
        var path = PresetFilePath;
        if (!File.Exists(path)) return [];
        try { return (JsonSerializer.Deserialize<List<LogSearchPreset>>(File.ReadAllText(path), JsonOptions) ?? []).Take(MaximumPresets).ToArray(); }
        catch (Exception ex) when (ex is IOException or JsonException) { throw new InvalidDataException($"Saved Log Lab filters could not be loaded: {ex.Message}", ex); }
    }

    public void Save(LogSearchPreset preset)
    {
        if (string.IsNullOrWhiteSpace(preset.Name) || preset.Name.Trim().Length > 80) throw new InvalidDataException("Filter name is required and must be 80 characters or fewer.");
        if (preset.Query.Length > 300 || preset.ComponentContains.Length > 200) throw new InvalidDataException("Search and component filters exceed their length limits.");
        var presets = Load().Where(item => !item.Name.Equals(preset.Name.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
        if (presets.Count >= MaximumPresets) throw new InvalidOperationException($"You can save up to {MaximumPresets} Log Lab filters.");
        presets.Add(preset with { Name = preset.Name.Trim() });
        Write(presets);
    }

    public void Delete(string name) => Write(Load().Where(item => !item.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray());

    private static void Write(IEnumerable<LogSearchPreset> presets)
    {
        var path = PresetFilePath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(presets, JsonOptions));
        File.Move(temp, path, overwrite: true);
    }
}
