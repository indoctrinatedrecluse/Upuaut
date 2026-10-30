using Markdig;
using Markdig.Renderers;
using System.IO;
using System.Text.RegularExpressions;

namespace Upuaut.UI.Components;

/// <summary>Renders provider/release Markdown without raw HTML, remote images, or unsafe link schemes.</summary>
public static partial class SafeMarkdownRenderer
{
    public const int MaximumCharacters = 512_000;
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder().UsePipeTables().UseTaskLists().UseAutoLinks().DisableHtml().Build();

    public static string Render(string? markdown)
    {
        var source = markdown ?? string.Empty;
        if (source.Length > MaximumCharacters) source = source[..MaximumCharacters] + "\n\n_The response was truncated by Upuaut._";
        var document = Markdown.Parse(source, Pipeline);
        using var writer = new StringWriter();
        var renderer = new HtmlRenderer(writer) { LinkRewriter = RewriteLink };
        Pipeline.Setup(renderer);
        renderer.Render(document);
        return ImageTag().Replace(writer.ToString(), string.Empty);
    }

    private static string RewriteLink(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var absolute))
            return absolute.Scheme is "https" or "http" or "mailto" ? url : string.Empty;
        return url.StartsWith('#') ? url : string.Empty;
    }

    [GeneratedRegex("<img\\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex ImageTag();
}
