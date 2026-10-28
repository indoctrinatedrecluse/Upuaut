using Upuaut.Core.Models;

namespace Upuaut.Core.Interfaces;

public interface IWeigherEngine
{
    IReadOnlyList<CorrelatedEvent> Analyze(
        IEnumerable<LogRecord> logRecords,
        IEnumerable<PacketFrame> packetFrames,
        TimeSpan correlationWindow);
}
