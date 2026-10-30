namespace Upuaut.LogLab.Models;

public interface ILlmAssistantService
{
    Task<string> AnalyzeAsync(string selectedLogEntry, CancellationToken cancellationToken = default);
}
