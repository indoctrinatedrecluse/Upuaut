using System.Diagnostics;

namespace Upuaut.Core.Diagnostics;

/// <summary>
/// Provides secure URL validation and launching.
/// Rejects dangerous schemes (file, cmd, powershell, javascript) to prevent arbitrary shell execution.
/// </summary>
public static class AppUrlLauncher
{
    /// <summary>
    /// Validates that the URL uses an authorized web scheme (HTTP or HTTPS) and launches it
    /// in the user's default operating system web browser.
    /// </summary>
    public static bool TryLaunchWebUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;

        var trimmed = url.Trim();
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            AppLogger.Warning("UrlLauncher", $"Rejected malformed URL: {trimmed}");
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            AppLogger.Warning("UrlLauncher", $"Rejected unauthorized URL scheme '{uri.Scheme}': {trimmed}");
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = uri.AbsoluteUri,
                UseShellExecute = true
            });
            return true;
        }
        catch (Exception ex)
        {
            AppLogger.Error("UrlLauncher", $"Failed to launch authorized URL {uri.AbsoluteUri}: {ex.Message}", ex);
            return false;
        }
    }
}
