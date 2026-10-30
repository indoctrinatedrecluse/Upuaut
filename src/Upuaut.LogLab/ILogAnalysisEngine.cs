using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogAnalysisEngine
{
    LogAnalysisReport Analyze(LogDocument document);
}
