using Upuaut.Core.Models;

namespace Upuaut.Core.Interfaces;

public interface IChroniclesService
{
    bool IsLiveTracing { get; }
    IReadOnlyList<string> GetAvailableChannels();
    Task<IReadOnlyList<LogRecord>> QueryEventLogsAsync(LogFilterOptions filter, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<LogRecord>> LoadEvtxFileAsync(string filePath, LogFilterOptions filter, CancellationToken cancellationToken = default);
    Task StartLiveStreamAsync(string channelName, HashSet<LogSeverityLevel> levels, CancellationToken cancellationToken = default);
    Task StopLiveStreamAsync();
    
    IReadOnlyList<EventCluster> ClusterLogs(IEnumerable<LogRecord> logs);
    string ExportLogs(IEnumerable<LogRecord> logs, LogExportFormat format);

    event EventHandler<LogRecord>? LogReceived;
    event EventHandler<string>? StatusChanged;
}
