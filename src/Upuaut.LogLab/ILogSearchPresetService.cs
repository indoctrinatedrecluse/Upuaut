using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogSearchPresetService
{
    IReadOnlyList<LogSearchPreset> Load();
    void Save(LogSearchPreset preset);
    void Delete(string name);
}
