using Upuaut.Core.Models;

namespace Upuaut.Core.Interfaces;

public record NetworkDeviceDescriptor(string Id, string Name, string Description, string? IpAddress);

public interface ICaptureEngine
{
    bool IsCapturing { get; }
    IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices();
    Task StartCaptureAsync(string deviceId, CancellationToken cancellationToken = default);
    Task StopCaptureAsync();
    event EventHandler<PacketFrame>? PacketReceived;
}
