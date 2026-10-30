namespace Upuaut.Core.Updates;

public sealed record UpdateRelease(string Version, string Name, string Notes, Uri DownloadUri);
