using System.Reflection;

namespace Upuaut.Core.Diagnostics;

/// <summary>Build metadata displayed consistently throughout the app.</summary>
public static class AppMetadata
{
    public const string FallbackVersion = "0.6.1";

    public static string DisplayVersion =>
        Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? FallbackVersion;
}
