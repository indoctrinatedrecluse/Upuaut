namespace Upuaut.Core.Updates;

public interface IUpdateService
{
    event Action? InstallerLaunched;
    Task<UpdateRelease?> CheckForUpdateAsync(CancellationToken cancellationToken = default);
    Task<string> DownloadAndLaunchInstallerAsync(UpdateRelease release, IProgress<double>? progress = null, CancellationToken cancellationToken = default);
}
