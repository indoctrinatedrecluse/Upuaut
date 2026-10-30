namespace Upuaut.LogLab.Models;

public enum LlmProvider
{
    DeepSeek,
    Gemini,
    OpenAiCompatible
}

public sealed record LlmAssistantConfiguration(
    LlmProvider Provider,
    string EndpointUrl,
    string Model,
    bool HasApiKey);

public interface ILlmAssistantService
{
    LlmAssistantConfiguration LoadConfiguration();
    void SaveConfiguration(LlmAssistantConfiguration configuration, string? apiKey);
    void ClearApiKey();
    Task<string> AnalyzeAsync(string selectedLogEntry, CancellationToken cancellationToken = default);
}
