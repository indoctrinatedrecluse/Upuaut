using Upuaut.UI.Components;

namespace Upuaut.Tests;

public sealed class AiMarkdownRenderingTests
{
    [Fact]
    public void Markdown_renderer_formats_content_and_blocks_raw_html_unsafe_links_and_remote_images()
    {
        const string markdown = "## Finding\n\n- **Observed:** timeout\n- Try `retry`\n\n<script>alert('x')</script>\n\n[unsafe](javascript:alert(1)) ![tracker](https://example.invalid/pixel.png)";

        var html = SafeMarkdownRenderer.Render(markdown);

        Assert.Contains("<h2>Finding</h2>", html);
        Assert.Contains("<strong>Observed:</strong>", html);
        Assert.Contains("<code>retry</code>", html);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("javascript:", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Markdown_renderer_bounds_large_provider_responses()
    {
        var html = SafeMarkdownRenderer.Render(new string('x', SafeMarkdownRenderer.MaximumCharacters + 1));

        Assert.Contains("The response was truncated by Upuaut.", html);
        Assert.True(html.Length < SafeMarkdownRenderer.MaximumCharacters + 256);
    }
}
