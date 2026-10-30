using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogSequenceAnalysisEngine
{
    IReadOnlyList<LogSequenceFinding> Analyze(LogDocument document, LogSequenceAnalysisOptions? options = null);
}
