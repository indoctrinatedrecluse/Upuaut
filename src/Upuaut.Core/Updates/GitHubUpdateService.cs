using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Upuaut.Core.Updates;

/// <summary>Checks the public GitHub latest-release API and stages the repository's standard setup bundle.</summary>
public sealed class GitHubUpdateService : IUpdateService
{
    private static readonly HttpClient Client = CreateClient();
    private const string LatestReleaseUrl = "https://api.github.com/repos/indoctrinatedrecluse/Upuaut/releases/latest";
    private const long MaximumDownloadBytes = 1_500_000_000;

    public event Action? InstallerLaunched;

    public async Task<UpdateRelease?> CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        using var response = await Client.GetAsync(LatestReleaseUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("GitHub returned an empty release response.");
        var versionText = release.TagName?.TrimStart('v', 'V');
        if (!Version.TryParse(versionText, out var latestVersion)) throw new InvalidDataException($"Release tag '{release.TagName}' is not a supported numeric version.");
        var currentVersion = Assembly.GetEntryAssembly()?.GetName().Version ?? new Version(0, 0, 0);
        if (latestVersion <= currentVersion) return null;
        var asset = release.Assets?.FirstOrDefault(item => item.Name?.Equals($"Upuaut-Setup-win-x64-v{versionText}.zip", StringComparison.OrdinalIgnoreCase) == true)
            ?? throw new InvalidDataException($"Release v{versionText} does not include the Upuaut Windows setup bundle.");
        if (!Uri.TryCreate(asset.BrowserDownloadUrl, UriKind.Absolute, out var downloadUri) || downloadUri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("The release setup download URL is invalid.");
        return new UpdateRelease(versionText!, release.Name ?? $"Upuaut v{versionText}", release.Body ?? string.Empty, downloadUri);
    }

    public async Task<string> DownloadAndLaunchInstallerAsync(UpdateRelease release, IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(release);
        var downloadRoot = Path.Combine(Path.GetTempPath(), "Upuaut", "Updates", Guid.NewGuid().ToString("N"));
        CleanupStaleUpdatePackages(Path.GetDirectoryName(downloadRoot)!);
        Directory.CreateDirectory(downloadRoot);
        var archivePath = Path.Combine(downloadRoot, "update.zip");
        using (var response = await Client.GetAsync(release.DownloadUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            var length = response.Content.Headers.ContentLength;
            if (length is > MaximumDownloadBytes) throw new InvalidDataException("The setup bundle exceeds the 1.5 GB safety limit.");
            await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using var destination = new FileStream(archivePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true);
            var buffer = new byte[81920];
            long received = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                received += read;
                if (received > MaximumDownloadBytes) throw new InvalidDataException("The setup bundle exceeded the 1.5 GB safety limit.");
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                if (length is > 0) progress?.Report(Math.Clamp(received * 100d / length.Value, 0, 100));
            }
        }

        var packageDirectory = Path.Combine(downloadRoot, "package");
        Directory.CreateDirectory(packageDirectory);
        ExtractArchiveSafely(archivePath, packageDirectory);
        File.Delete(archivePath);
        var installer = Path.Combine(packageDirectory, "Upuaut.Setup.exe");
        if (!File.Exists(installer) || !Directory.Exists(Path.Combine(packageDirectory, "payload")))
            throw new InvalidDataException("The downloaded release bundle is incomplete; setup executable or payload is missing.");

        Process.Start(new ProcessStartInfo(installer) { WorkingDirectory = packageDirectory, UseShellExecute = true });
        InstallerLaunched?.Invoke();
        return packageDirectory;
    }

    private static void CleanupStaleUpdatePackages(string updateDirectory)
    {
        try
        {
            if (!Directory.Exists(updateDirectory)) return;
            foreach (var directory in Directory.EnumerateDirectories(updateDirectory))
                if (Directory.GetLastWriteTimeUtc(directory) < DateTime.UtcNow.AddDays(-14))
                    Directory.Delete(directory, recursive: true);
        }
        catch { /* Old staging cleanup is best-effort and must not block checking or installing an update. */ }
    }

    private static void ExtractArchiveSafely(string archivePath, string destinationRoot)
    {
        var root = Path.GetFullPath(destinationRoot) + Path.DirectorySeparatorChar;
        using var archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count > 100_000) throw new InvalidDataException("The setup archive has too many entries.");
        long expandedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            var destination = Path.GetFullPath(Path.Combine(destinationRoot, entry.FullName));
            if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("The setup archive contains an unsafe path.");
            expandedBytes = checked(expandedBytes + entry.Length);
            if (expandedBytes > 2_500_000_000) throw new InvalidDataException("The expanded setup bundle exceeds the 2.5 GB safety limit.");
            if (string.IsNullOrEmpty(entry.Name)) { Directory.CreateDirectory(destination); continue; }
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            entry.ExtractToFile(destination, overwrite: true);
        }
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(15) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Upuaut", Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "0.0.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return client;
    }

    private sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string? TagName { get; init; }
        [JsonPropertyName("name")] public string? Name { get; init; }
        [JsonPropertyName("body")] public string? Body { get; init; }
        [JsonPropertyName("assets")] public GitHubAsset[]? Assets { get; init; }
    }

    private sealed class GitHubAsset
    {
        [JsonPropertyName("name")] public string? Name { get; init; }
        [JsonPropertyName("browser_download_url")] public string? BrowserDownloadUrl { get; init; }
    }
}
