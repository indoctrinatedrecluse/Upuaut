using Upuaut.Core.Buffers;
using Upuaut.Core.Diagnostics;
using Upuaut.Core.Interfaces;
using Upuaut.Core.Models;
using Upuaut.Scout.Capture;

namespace Upuaut.Scout.Services;

public record ScoutStatistics(
    long TotalPackets,
    long TotalBytes,
    double PacketsPerSecond,
    IReadOnlyDictionary<NetworkProtocol, int> ProtocolDistribution,
    IReadOnlyDictionary<string, int> TopProcesses);

/// <summary>
/// Central manager for the Scout packet sniffing subsystem.
/// Controls active capture engines, maintains the live frame buffer, and computes real-time telemetry.
/// </summary>
public class ScoutManager : ICaptureEngine, IDisposable
{
    private readonly ICaptureEngine _engine;
    private readonly RingBuffer<PacketFrame> _buffer = new(15000);
    private long _totalPackets;
    private long _totalBytes;
    private DateTime _captureStartedAt = DateTime.UtcNow;

    public bool IsCapturing => _engine.IsCapturing;
    public int BufferCount => _buffer.Count;
    public int BufferCapacity => _buffer.Capacity;

    public event EventHandler<PacketFrame>? PacketReceived;

    public ScoutManager()
    {
        // By default, initialize with driverless native Windows raw socket engine
        _engine = new RawSocketCaptureEngine();
        _engine.PacketReceived += OnPacketCaptured;
    }

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices()
    {
        return _engine.GetAvailableDevices();
    }

    public async Task StartCaptureAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        _captureStartedAt = DateTime.UtcNow;
        AppLogger.Info("ScoutManager", $"Starting packet capture on adapter: {deviceId}");
        await _engine.StartCaptureAsync(deviceId, cancellationToken);
    }

    public async Task StopCaptureAsync()
    {
        AppLogger.Info("ScoutManager", "Stopping packet capture.");
        await _engine.StopCaptureAsync();
    }

    public void ClearBuffer()
    {
        // Clear snapshot by draining or re-initializing
        _totalPackets = 0;
        _totalBytes = 0;
    }

    public IReadOnlyList<PacketFrame> GetRecentFrames(
        NetworkProtocol? protocolFilter = null,
        string? processFilter = null,
        string? searchFilter = null,
        int maxFrames = 500)
    {
        var snapshot = _buffer.ToSnapshot();
        var query = snapshot.AsEnumerable();

        if (protocolFilter.HasValue && protocolFilter.Value != NetworkProtocol.Unknown)
        {
            query = query.Where(f => f.Protocol == protocolFilter.Value);
        }

        if (!string.IsNullOrWhiteSpace(processFilter))
        {
            query = query.Where(f => f.ProcessName?.Equals(processFilter, StringComparison.OrdinalIgnoreCase) ?? false);
        }

        if (!string.IsNullOrWhiteSpace(searchFilter))
        {
            var s = searchFilter.Trim();
            query = query.Where(f =>
                f.SourceIp.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                f.DestinationIp.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                f.Summary.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                (f.ProcessName?.Contains(s, StringComparison.OrdinalIgnoreCase) ?? false) ||
                f.SourcePort?.ToString() == s ||
                f.DestinationPort?.ToString() == s);
        }

        return query.TakeLast(maxFrames).Reverse().ToList();
    }

    public ScoutStatistics GetStatistics()
    {
        var snapshot = _buffer.ToSnapshot();
        var elapsedSec = Math.Max(0.5, (DateTime.UtcNow - _captureStartedAt).TotalSeconds);
        var pps = _engine.IsCapturing ? (snapshot.Count / elapsedSec) : 0;

        var protoDist = snapshot
            .GroupBy(f => f.Protocol)
            .ToDictionary(g => g.Key, g => g.Count());

        var procDist = snapshot
            .Where(f => !string.IsNullOrEmpty(f.ProcessName))
            .GroupBy(f => f.ProcessName!)
            .OrderByDescending(g => g.Count())
            .Take(8)
            .ToDictionary(g => g.Key, g => g.Count());

        return new ScoutStatistics(
            TotalPackets: _totalPackets,
            TotalBytes: _totalBytes,
            PacketsPerSecond: pps,
            ProtocolDistribution: protoDist,
            TopProcesses: procDist);
    }

    private void OnPacketCaptured(object? sender, PacketFrame frame)
    {
        Interlocked.Increment(ref _totalPackets);
        Interlocked.Add(ref _totalBytes, frame.TotalLength);

        _buffer.Add(frame);

        try
        {
            PacketReceived?.Invoke(this, frame);
        }
        catch
        {
            // Ignore subscriber error
        }
    }

    public void Dispose()
    {
        _engine.PacketReceived -= OnPacketCaptured;
        if (_engine is IDisposable d) d.Dispose();
    }
}
