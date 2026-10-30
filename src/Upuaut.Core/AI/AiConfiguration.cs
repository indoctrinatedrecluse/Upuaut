namespace Upuaut.Core.AI;

/// <summary>Provider-neutral settings shared by optional AI integrations.</summary>
public enum AiProvider { DeepSeek, Gemini, OpenAiCompatible }

public sealed record AiConfiguration(AiProvider Provider, string EndpointUrl, string Model, bool HasApiKey);

/// <summary>Local credential/configuration contract available to any app service.</summary>
public interface IAiConfigurationService
{
    AiConfiguration LoadConfiguration();
    void SaveConfiguration(AiConfiguration configuration, string? apiKey);
    void ClearApiKey();
    /// <summary>Returns the decrypted key for an explicit in-process provider request; callers must never log or persist it.</summary>
    string GetApiKeyForRequest();
}
