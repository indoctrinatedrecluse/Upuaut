using Upuaut.Core.Models;

namespace Upuaut.Core.Interfaces;

public interface IChroniclesService
{
    bool IsLiveTracing { get; }
    Task<IReadOnlyList<LogRecord>> QueryEventLogsAsync(
        string channelName = "System",
        int maxCount = 500,
        LogSeverityLevel? minLevel = null,
        CancellationToken cancellationToken = default);

    Task StartLiveTraceAsync(CancellationToken cancellationToken = default);
    Task StopLiveTraceAsync();
    event EventHandler<LogRecord>? LogReceived;
}
