using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogReportExporter
{
    string ExportMarkdown(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences, LogTimelineReport? timeline = null, LogSequenceAnalysisOptions? sequenceOptions = null, LogReportOptions? options = null);
    string ExportJson(LogDocument document, LogAnalysisReport analysis, IReadOnlyList<LogSequenceFinding> sequences, LogTimelineReport? timeline = null, LogSequenceAnalysisOptions? sequenceOptions = null, LogReportOptions? options = null);
}
