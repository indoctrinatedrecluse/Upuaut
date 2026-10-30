using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogParserProfileService
{
    IReadOnlyList<LogParserProfile> LoadProfiles();
    IReadOnlyList<LogParserProfile> GetBuiltInProfiles();
    LogParserProfile ParseAndValidate(string json);
    string Serialize(LogParserProfile profile);
    void SaveProfile(LogParserProfile profile);
    void DeleteProfile(string name);
    LogProfileApplyResult Apply(LogDocument document, LogParserProfile profile);
}
