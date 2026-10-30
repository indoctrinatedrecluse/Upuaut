using Upuaut.Core.Models;

namespace Upuaut.Core.Interfaces;

public record NetworkDeviceDescriptor(string Id, string Name, string Description, string? IpAddress);

public enum PacketCaptureMode { RawIpv4, Ethernet }

public interface ICaptureEngine
{
    bool IsCapturing { get; }
    IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices();
    IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices(PacketCaptureMode mode);
    Task StartCaptureAsync(string deviceId, CancellationToken cancellationToken = default);
    Task StartCaptureAsync(string deviceId, PacketCaptureMode mode, CancellationToken cancellationToken = default);
    Task StopCaptureAsync();
    event EventHandler<PacketFrame>? PacketReceived;
}
