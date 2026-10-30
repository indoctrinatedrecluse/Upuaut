namespace Upuaut.LogLab.Models;

public sealed record LogSearchPreset(
    string Name,
    string Query,
    string Severity,
    string Category,
    string ComponentContains,
    string FromLocal,
    string ToLocal);
