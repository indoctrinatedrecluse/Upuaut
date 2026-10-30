using Upuaut.CrashForensics.Models;

namespace Upuaut.CrashForensics;

public interface ICrashArtifactAnalyzer
{
    Task<CrashAnalysisResult> AnalyzeAsync(string path, bool resolveMicrosoftSymbols = false, CancellationToken cancellationToken = default);
}
