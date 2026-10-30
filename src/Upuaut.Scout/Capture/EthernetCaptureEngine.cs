using SharpPcap;
using Upuaut.Core.Diagnostics;
using Upuaut.Core.Interfaces;
using Upuaut.Core.Models;
using Upuaut.Scout.Parsers;

namespace Upuaut.Scout.Capture;

/// <summary>Link-layer capture through SharpPcap. Requires a compatible capture provider such as Npcap.</summary>
public sealed class EthernetCaptureEngine : ICaptureEngine, IDisposable
{
    private ICaptureDevice? _device;
    private CancellationTokenRegistration _cancellationRegistration;
    private long _frameNumber;
    private readonly object _sync = new();
    private long _receivedPacketCount, _rejectedPacketCount;
    public long ReceivedPacketCount => Interlocked.Read(ref _receivedPacketCount);
    public long RejectedPacketCount => Interlocked.Read(ref _rejectedPacketCount);

    public bool IsCapturing { get; private set; }
    public event EventHandler<PacketFrame>? PacketReceived;

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices()
    {
        try
        {
            return CaptureDeviceList.Instance.Select(d => new NetworkDeviceDescriptor(
                d.Name, d.Name, d.Description ?? d.Name, null)).ToArray();
        }
        catch (Exception ex)
        {
            AppLogger.Warning("EthernetCapture", $"Unable to enumerate packet capture devices: {ex.Message}");
            return Array.Empty<NetworkDeviceDescriptor>();
        }
    }

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices(PacketCaptureMode mode) => GetAvailableDevices();

    public Task StartCaptureAsync(string deviceId, CancellationToken cancellationToken = default) =>
        StartCaptureAsync(deviceId, PacketCaptureMode.Ethernet, cancellationToken);

    public Task StartCaptureAsync(string deviceId, PacketCaptureMode mode, CancellationToken cancellationToken = default)
    {
        if (mode != PacketCaptureMode.Ethernet) throw new NotSupportedException("Ethernet capture requires Ethernet mode.");
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (IsCapturing) return Task.CompletedTask;
            var device = CaptureDeviceList.Instance.FirstOrDefault(d => d.Name == deviceId)
                ?? throw new InvalidOperationException($"Capture adapter '{deviceId}' is unavailable. Install or repair Npcap if no adapters are listed.");
            try
            {
                device.Open(DeviceModes.Promiscuous, 1000);
                device.OnPacketArrival += OnPacketArrival;
                _device = device;
                _frameNumber = 0;
                Interlocked.Exchange(ref _receivedPacketCount, 0); Interlocked.Exchange(ref _rejectedPacketCount, 0);
                IsCapturing = true;
                device.StartCapture();
                AppLogger.Info("EthernetCapture", $"Link-layer capture started on {device.Description}.");
            }
            catch
            {
                IsCapturing = false;
                device.OnPacketArrival -= OnPacketArrival;
                try { device.Close(); } catch { }
                _device = null;
                throw;
            }
        }
        var registration = cancellationToken.Register(() => _ = StopCaptureAsync());
        lock (_sync)
        {
            if (IsCapturing) _cancellationRegistration = registration;
            else registration.Dispose();
        }
        return Task.CompletedTask;
    }

    private void OnPacketArrival(object sender, PacketCapture capture)
    {
        Interlocked.Increment(ref _receivedPacketCount);
        PacketFrame? frame;
        try
        {
            var raw = capture.GetPacket();
            frame = PacketParser.ParseEthernetFrame(raw.Data, raw.Data.Length, Interlocked.Increment(ref _frameNumber), _device?.Description);
        }
        catch (Exception ex) { Interlocked.Increment(ref _rejectedPacketCount); AppLogger.Debug("EthernetCapture", $"Rejected frame after parse error: {ex.Message}"); return; }
        if (frame is null) { Interlocked.Increment(ref _rejectedPacketCount); return; }
        try { PacketReceived?.Invoke(this, frame); }
        catch (Exception ex) { AppLogger.Debug("EthernetCapture", $"Packet subscriber failed: {ex.Message}"); }
    }

    public Task StopCaptureAsync()
    {
        lock (_sync)
        {
            if (!IsCapturing) return Task.CompletedTask;
            IsCapturing = false;
            _cancellationRegistration.Dispose();
            if (_device is { } device)
            {
                device.OnPacketArrival -= OnPacketArrival;
                try { device.StopCapture(); } catch (Exception ex) { AppLogger.Debug("EthernetCapture", ex.Message); }
                try { device.Close(); } catch (Exception ex) { AppLogger.Debug("EthernetCapture", ex.Message); }
                _device = null;
            }
        }
        return Task.CompletedTask;
    }

    public void Dispose() => StopCaptureAsync().GetAwaiter().GetResult();
}
