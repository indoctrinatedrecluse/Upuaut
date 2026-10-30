using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogReportExporter
{
    string ExportMarkdown(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences);
    string ExportJson(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences);
}
