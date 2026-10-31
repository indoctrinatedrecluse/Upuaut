using System.Net;
using System.Net.Http;
using System.IO;
using System.Net.Http.Headers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Upuaut.LogLab;
using Upuaut.LogLab.Models;
using Upuaut.Core.AI;

namespace Upuaut.UI.Services;

/// <summary>Opt-in remote review with current-user DPAPI storage. Never logs request or credential contents.</summary>
public sealed class LocalLlmAssistantService : ILlmAssistantService, IAiConfigurationService, IDisposable
{
    private const int MaximumResponseBytes = 512_000;

    /// <summary>
    /// Output ceiling requested from the provider. Reasoning-capable models spend part of this
    /// budget on internal reasoning, so the ceiling leaves room for a complete Markdown review.
    /// </summary>
    private const int MaximumOutputTokens = 3_000;
    private const string DefaultDeepSeekEndpoint = "https://api.deepseek.com/chat/completions";
    private const string DefaultGeminiEndpoint = "https://generativelanguage.googleapis.com/v1beta";
    private const string DefaultGeminiModel = "gemini-3.8-flash";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Upuaut.LogLab.LocalAssistant.v1");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 64 };
    private readonly HttpClient _http = new(new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
        ConnectTimeout = TimeSpan.FromSeconds(15),
        PooledConnectionLifetime = TimeSpan.FromMinutes(10)
    }) { Timeout = TimeSpan.FromSeconds(70) };
    private readonly string _settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Upuaut", "Settings", "llm-assistant.json");
    private readonly object _gate = new();
    private StoredConfiguration _stored = new(AiProvider.DeepSeek, DefaultDeepSeekEndpoint, "deepseek-flash", null);

    public LocalLlmAssistantService() => LoadStored();

    public AiConfiguration LoadConfiguration()
    {
        lock (_gate) return new(_stored.Provider, _stored.EndpointUrl, _stored.Model, !string.IsNullOrWhiteSpace(_stored.ProtectedApiKey));
    }

    public void SaveConfiguration(AiConfiguration configuration, string? apiKey)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (!Enum.IsDefined(configuration.Provider)) throw new InvalidOperationException("Choose a supported AI provider.");
        var endpoint = ValidateEndpoint(configuration.Provider, configuration.EndpointUrl);
        var model = ValidateShortValue(configuration.Model, "Model", 128);
        if (!string.IsNullOrWhiteSpace(apiKey) && (apiKey.Length > 4096 || apiKey.Any(char.IsControl))) throw new InvalidOperationException("The API key has an invalid length or contains control characters.");
        string? protectedKey;
        lock (_gate)
        {
            protectedKey = string.IsNullOrWhiteSpace(apiKey) ? _stored.ProtectedApiKey : Protect(apiKey.Trim());
            if (string.IsNullOrWhiteSpace(protectedKey)) throw new InvalidOperationException("Enter an API key before saving the assistant settings.");
            _stored = new StoredConfiguration(configuration.Provider, endpoint, model, protectedKey);
            Persist();
        }
    }

    public void ClearApiKey()
    {
        lock (_gate)
        {
            _stored = _stored with { ProtectedApiKey = null };
            Persist();
        }
    }

    public string GetApiKeyForRequest()
    {
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(_stored.ProtectedApiKey)) throw new InvalidOperationException("Configure and save an API key before requesting an AI review.");
            return Unprotect(_stored.ProtectedApiKey);
        }
    }

    public Task<string> AnalyzeAsync(string selectedLogEntry, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(selectedLogEntry)) throw new InvalidOperationException("Select an item before requesting an AI review.");
        return AnalyzeInvestigationAsync(AiPromptEngine.BuildLegacyEntryRequest(selectedLogEntry), cancellationToken);
    }

    public async Task<string> AnalyzeInvestigationAsync(AiInvestigationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.UserPrompt)) throw new InvalidOperationException("Select an item before requesting an AI review.");
        if (request.UserPrompt.Length > AiPromptEngine.MaximumAcceptedCharacters) throw new InvalidOperationException($"The request exceeds the {AiPromptEngine.MaximumAcceptedCharacters:N0}-character AI review limit. Select a shorter unit or use local analysis only.");

        // Defense in depth: requests built outside AiPromptEngine still receive the hard ceiling and a budget report.
        request = AiPromptEngine.EnforceBudget(request);

        StoredConfiguration configuration;
        string key;
        lock (_gate)
        {
            configuration = _stored with { EndpointUrl = ValidateEndpoint(_stored.Provider, _stored.EndpointUrl) };
            if (string.IsNullOrWhiteSpace(configuration.ProtectedApiKey)) throw new InvalidOperationException("Configure and save an API key before requesting an AI review.");
            key = Unprotect(configuration.ProtectedApiKey);
        }

        using var httpRequest = configuration.Provider == AiProvider.Gemini
            ? BuildGeminiInvestigationRequest(configuration, key, request)
            : BuildChatInvestigationRequest(configuration, key, request);
        using var response = await _http.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var detail = await ReadBoundedBodyAsync(response.Content, 32_000, cancellationToken).ConfigureAwait(false);
            var providerMessage = AiResponseParser.ExtractProviderErrorMessage(detail);
            if (!string.IsNullOrWhiteSpace(key)) providerMessage = providerMessage.Replace(key, "[redacted]", StringComparison.Ordinal);
            throw new HttpRequestException(FormatProviderError(response.StatusCode, providerMessage));
        }

        var body = await ReadBoundedBodyAsync(response.Content, MaximumResponseBytes, cancellationToken).ConfigureAwait(false);
        return AiResponseParser.ExtractAssistantText(body, configuration.Provider);
    }

    public void Dispose() => _http.Dispose();

    private static HttpRequestMessage BuildChatInvestigationRequest(StoredConfiguration configuration, string key, AiInvestigationRequest req)
    {
        var endpoint = BuildChatEndpoint(configuration.EndpointUrl);
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var payload = new
        {
            model = configuration.Model,
            temperature = 0.2,
            max_tokens = MaximumOutputTokens,
            stream = false,
            messages = new object[]
            {
                new { role = "system", content = req.SystemInstruction },
                new { role = "user", content = req.UserPrompt }
            }
        };
        request.Content = new StringContent(JsonSerializer.Serialize(payload, JsonOptions), Encoding.UTF8, "application/json");
        return request;
    }

    private static HttpRequestMessage BuildGeminiInvestigationRequest(StoredConfiguration configuration, string key, AiInvestigationRequest req)
    {
        var endpoint = BuildGeminiEndpoint(configuration.EndpointUrl, configuration.Model);
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        request.Headers.Add("x-goog-api-key", key);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var payload = new
        {
            system_instruction = new
            {
                parts = new[] { new { text = req.SystemInstruction } }
            },
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = new[] { new { text = req.UserPrompt } }
                }
            },
            generationConfig = new
            {
                temperature = 0.2,
                maxOutputTokens = MaximumOutputTokens
            }
        };
        request.Content = new StringContent(JsonSerializer.Serialize(payload, JsonOptions), Encoding.UTF8, "application/json");
        return request;
    }

    private static Uri BuildChatEndpoint(string value)
    {
        var uri = new Uri(value, UriKind.Absolute);
        if (uri.AbsolutePath.TrimEnd('/').EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase)) return uri;
        return new Uri(uri.ToString().TrimEnd('/') + "/chat/completions", UriKind.Absolute);
    }

    private static Uri BuildGeminiEndpoint(string value, string model)
    {
        var uri = new Uri(value, UriKind.Absolute);
        var path = uri.AbsolutePath.TrimEnd('/');
        if (path.EndsWith(":generateContent", StringComparison.OrdinalIgnoreCase)) return uri;
        var modelName = model.StartsWith("models/", StringComparison.OrdinalIgnoreCase) ? model["models/".Length..] : model;
        var builder = new UriBuilder(uri) { Path = path + "/models/" + Uri.EscapeDataString(modelName) + ":generateContent", Query = string.Empty };
        return builder.Uri;
    }

    private static string ValidateEndpoint(AiProvider provider, string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint) || endpoint.Length > 2048 || !Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out var uri))
            throw new InvalidOperationException("Enter a valid absolute provider endpoint URL.");
        var localHttp = uri.Scheme == Uri.UriSchemeHttp && (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase));
        if (uri.Scheme != Uri.UriSchemeHttps && !localHttp) throw new InvalidOperationException("Provider endpoints must use HTTPS. HTTP is permitted only for a localhost endpoint.");
        if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.Query)) throw new InvalidOperationException("Do not place credentials, query parameters, or fragments in the endpoint URL.");
        return uri.ToString().TrimEnd('/');
    }

    private static string ValidateShortValue(string value, string label, int maximum)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length is 0 || normalized.Length > maximum || normalized.Any(char.IsControl)) throw new InvalidOperationException($"Enter a valid {label.ToLowerInvariant()} (up to {maximum} characters).");
        return normalized;
    }

    private static string FormatProviderError(HttpStatusCode statusCode, string providerMessage)
    {
        var guidance = statusCode switch
        {
            HttpStatusCode.Unauthorized => "Check the saved API key and selected provider.",
            HttpStatusCode.Forbidden => "Check the key's account permissions, region, and model access.",
            HttpStatusCode.NotFound => "Check the endpoint path and model identifier.",
            HttpStatusCode.TooManyRequests => "The provider rate or quota limit may have been reached; wait before manually retrying.",
            HttpStatusCode.RequestEntityTooLarge => "The provider rejected the request size.",
            HttpStatusCode.RequestTimeout or HttpStatusCode.GatewayTimeout => "The provider request timed out; check the endpoint and provider status.",
            _ when (int)statusCode >= 500 => "The provider or an upstream service reported a server error.",
            _ => "Check the provider response and endpoint settings."
        };
        return $"Provider returned {(int)statusCode} ({statusCode}). {guidance}{(string.IsNullOrWhiteSpace(providerMessage) ? string.Empty : " Provider detail: " + ClipProviderText(providerMessage))}";
    }

    private static string ClipProviderText(string value)
    {
        var clean = new string((value ?? string.Empty).Where(character => !char.IsControl(character) || character is '\r' or '\n' or '\t').ToArray());
        clean = string.Join(' ', clean.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return clean.Length <= 500 ? clean : clean[..497] + "...";
    }
    private static async Task<string> ReadBoundedBodyAsync(HttpContent content, int maximumBytes, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > 0 and var length && length > maximumBytes) throw new InvalidDataException("The provider response exceeded the configured size limit.");
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(Math.Min(maximumBytes, 16_384));
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > maximumBytes) throw new InvalidDataException("The provider response exceeded the configured size limit.");
            output.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(output.GetBuffer(), 0, checked((int)output.Length));
    }

    private void LoadStored()
    {
        try
        {
            if (!File.Exists(_settingsPath)) return;
            var stored = JsonSerializer.Deserialize<StoredConfiguration>(File.ReadAllText(_settingsPath), JsonOptions);
            if (stored is not null && Enum.IsDefined(stored.Provider) && Uri.TryCreate(stored.EndpointUrl, UriKind.Absolute, out _)) _stored = stored;
        }
        catch { _stored = new(AiProvider.DeepSeek, DefaultDeepSeekEndpoint, "deepseek-flash", null); }
    }

    private void Persist()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
        var tempPath = _settingsPath + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(_stored, JsonOptions), new UTF8Encoding(false));
        File.Move(tempPath, _settingsPath, true);
    }

    private static string Protect(string value)
    {
        var protectedBytes = TransformDpapi(Encoding.UTF8.GetBytes(value), protect: true);
        try { return Convert.ToBase64String(protectedBytes); }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }
    private static string Unprotect(string protectedValue)
    {
        byte[]? clearBytes = null;
        try { clearBytes = TransformDpapi(Convert.FromBase64String(protectedValue), protect: false); return Encoding.UTF8.GetString(clearBytes); }
        catch (Exception ex) when (ex is FormatException or CryptographicException or Win32Exception) { throw new InvalidOperationException("The saved API key could not be decrypted for this Windows account. Re-enter the key in AI settings."); }
        finally { if (clearBytes is not null) CryptographicOperations.ZeroMemory(clearBytes); }
    }

    private static byte[] TransformDpapi(byte[] input, bool protect)
    {
        var inputPointer = IntPtr.Zero;
        var entropyPointer = IntPtr.Zero;
        DataBlob outputBlob = default;
        try
        {
            inputPointer = Marshal.AllocHGlobal(input.Length);
            entropyPointer = Marshal.AllocHGlobal(Entropy.Length);
            Marshal.Copy(input, 0, inputPointer, input.Length);
            Marshal.Copy(Entropy, 0, entropyPointer, Entropy.Length);
            var inputBlob = new DataBlob(input.Length, inputPointer);
            var entropyBlob = new DataBlob(Entropy.Length, entropyPointer);
            var success = protect
                ? CryptProtectData(ref inputBlob, "Upuaut shared AI API key", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 1, out outputBlob)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 1, out outputBlob);
            if (!success) throw new Win32Exception(Marshal.GetLastWin32Error());
            var output = new byte[outputBlob.Size];
            Marshal.Copy(outputBlob.Data, output, 0, output.Length);
            return output;
        }
        finally
        {
            if (inputPointer != IntPtr.Zero)
            {
                var zeroInput = new byte[input.Length];
                Marshal.Copy(zeroInput, 0, inputPointer, zeroInput.Length);
                CryptographicOperations.ZeroMemory(zeroInput);
            }
            if (inputPointer != IntPtr.Zero) Marshal.FreeHGlobal(inputPointer);
            if (entropyPointer != IntPtr.Zero) Marshal.FreeHGlobal(entropyPointer);
            if (outputBlob.Data != IntPtr.Zero)
            {
                var zeroOutput = new byte[outputBlob.Size];
                Marshal.Copy(zeroOutput, 0, outputBlob.Data, zeroOutput.Length);
                CryptographicOperations.ZeroMemory(zeroOutput);
                LocalFree(outputBlob.Data);
            }
            CryptographicOperations.ZeroMemory(input);
        }
    }

    [StructLayout(LayoutKind.Sequential)] private struct DataBlob(int size, IntPtr data) { public int Size = size; public IntPtr Data = data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref DataBlob input, string? description, ref DataBlob optionalEntropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob optionalEntropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);

    private sealed record StoredConfiguration(AiProvider Provider, string EndpointUrl, string Model, string? ProtectedApiKey);
}
