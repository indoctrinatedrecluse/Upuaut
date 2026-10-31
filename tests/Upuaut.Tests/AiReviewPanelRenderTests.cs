using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Upuaut.Core.AI;
using Upuaut.UI.Components;

namespace Upuaut.Tests;

/// <summary>
/// Guards the v0.6.1 fix: the shared AI review panel must render its entry point in every
/// workspace, even before a unit is selected or before an API key is configured.
/// </summary>
public sealed class AiReviewPanelRenderTests
{
    [Fact]
    public async Task Unconfigured_profile_renders_setup_guidance_and_configure_button()
    {
        var html = await RenderPanelAsync(hasApiKey: false, selectionKey: null, requestFactory: null);

        Assert.Contains("AI FRAME REVIEW", html);
        Assert.Contains("DISABLED", html);
        Assert.Contains("REQUEST AI REVIEW", html);
        Assert.Contains("HOW TO ENABLE AI REVIEWS HERE", html);
        Assert.Contains("CONFIGURE AI SERVICES", html);
        Assert.Contains("dpapi", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Configured_profile_without_a_selection_renders_the_empty_hint()
    {
        var html = await RenderPanelAsync(hasApiKey: true, selectionKey: null, requestFactory: null);

        Assert.Contains("ON REQUEST", html);
        Assert.Contains("Select a captured frame in the packet grid to enable AI review.", html);
        Assert.DoesNotContain("HOW TO ENABLE AI REVIEWS HERE", html);
        Assert.Contains("disabled", html);
    }

    [Fact]
    public async Task Configured_profile_with_a_selection_enables_the_review_button()
    {
        var html = await RenderPanelAsync(
            hasApiKey: true,
            selectionKey: "17",
            requestFactory: (Func<AiInvestigationRequest?>)(() => null));

        Assert.Contains("ON REQUEST", html);
        Assert.Contains("Only this frame is submitted", html);
        Assert.DoesNotContain("HOW TO ENABLE AI REVIEWS HERE", html);
        Assert.DoesNotContain("Select a captured frame in the packet grid", html);
        Assert.DoesNotContain("disabled", html);
    }

    private static async Task<string> RenderPanelAsync(bool hasApiKey, string? selectionKey, Func<AiInvestigationRequest?>? requestFactory)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAiConfigurationService>(new StubConfigurationService(hasApiKey));
        services.AddSingleton<ILlmAssistantService>(new StubAssistantService());
        services.AddSingleton<AiSettingsDialogCoordinator>();

        using var provider = services.BuildServiceProvider();
        using var renderer = new HtmlRenderer(provider, provider.GetRequiredService<ILoggerFactory>());

        return await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var parameters = ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                [nameof(AiReviewPanel.Title)] = "AI FRAME REVIEW",
                [nameof(AiReviewPanel.ScopeNote)] = "Only this frame is submitted: decoded headers and a printable payload preview.",
                [nameof(AiReviewPanel.EmptyHint)] = "Select a captured frame in the packet grid to enable AI review.",
                [nameof(AiReviewPanel.SelectionKey)] = selectionKey,
                [nameof(AiReviewPanel.RequestFactory)] = requestFactory
            });

            var output = await renderer.RenderComponentAsync<AiReviewPanel>(parameters);
            return output.ToHtmlString();
        });
    }

    private sealed class StubConfigurationService(bool hasApiKey) : IAiConfigurationService
    {
        private AiConfiguration _configuration = new(AiProvider.DeepSeek, "https://api.deepseek.com/chat/completions", "deepseek-flash", hasApiKey);

        public AiConfiguration LoadConfiguration() => _configuration;

        public void SaveConfiguration(AiConfiguration configuration, string? apiKey) => _configuration = configuration;

        public void ClearApiKey() => _configuration = _configuration with { HasApiKey = false };

        public string GetApiKeyForRequest() => hasApiKey ? "stub-key" : throw new InvalidOperationException("No key configured.");
    }

    private sealed class StubAssistantService : ILlmAssistantService
    {
        public Task<string> AnalyzeAsync(string selectedLogEntry, CancellationToken cancellationToken = default)
            => Task.FromResult(string.Empty);

        public Task<string> AnalyzeInvestigationAsync(AiInvestigationRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(string.Empty);
    }
}
