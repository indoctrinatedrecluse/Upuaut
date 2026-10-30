using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

public interface ILogParsingEngine
{
    const long DefaultMaximumFileBytes = 32 * 1024 * 1024;

    Task<LogDocument> ImportFileAsync(string path, CancellationToken cancellationToken = default);
    IReadOnlyList<ParsedLogEntry> Search(LogDocument document, LogSearchOptions options);
    string FormatJson(string text);
    string FormatXml(string text);
}
