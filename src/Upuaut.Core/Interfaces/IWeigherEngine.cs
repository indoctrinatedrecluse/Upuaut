using Upuaut.Core.Models;

namespace Upuaut.Core.Interfaces;

/// <summary>
/// Service contract for cross-source log and network packet temporal correlation,
/// timeline ranking, and incident case persistence.
/// </summary>
public interface IWeigherEngine
{
    /// <summary>
    /// Correlates a sequence of log records against buffered network packets and sibling logs
    /// using temporal sliding-window proximity and identifier matching.
    /// </summary>
    IReadOnlyList<TriageItem> Correlate(
        IEnumerable<LogRecord> logs,
        IEnumerable<PacketFrame> packets,
        TimeSpan? correlationWindow = null);

    /// <summary>
    /// Analyzes logs and packet frames over a given window to produce high-level correlated event entities.
    /// </summary>
    IReadOnlyList<CorrelatedEvent> Analyze(
        IEnumerable<LogRecord> logRecords,
        IEnumerable<PacketFrame> packetFrames,
        TimeSpan correlationWindow);

    /// <summary>
    /// Serializes an investigation case snapshot to sanitized JSON.
    /// </summary>
    string ExportCaseJson(TriageCase triageCase);

    /// <summary>
    /// Deserializes an investigation case snapshot from JSON.
    /// </summary>
    TriageCase DeserializeCaseJson(string json);

    /// <summary>
    /// Exports triage items and case notes to CSV with formula injection protection.
    /// </summary>
    string ExportCaseCsv(IEnumerable<TriageItem> items, IReadOnlyDictionary<string, string>? notes = null);
}
