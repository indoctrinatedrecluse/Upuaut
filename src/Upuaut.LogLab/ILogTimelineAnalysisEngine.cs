using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogTimelineAnalysisEngine
{
    LogTimelineReport Analyze(LogDocument document, int intervalMinutes = 5);
}
