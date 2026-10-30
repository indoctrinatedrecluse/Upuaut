using Upuaut.Core.Buffers;
using Upuaut.Core.Diagnostics;
using Upuaut.Core.Interfaces;
using Upuaut.Core.Models;
using Upuaut.Scout.Capture;
using System.Collections.Concurrent;

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
    private readonly RawSocketCaptureEngine _rawEngine;
    private readonly EthernetCaptureEngine _ethernetEngine;
    private ICaptureEngine? _activeEngine;
    private readonly RingBuffer<PacketFrame> _buffer = new(15000);
    private readonly ConcurrentQueue<DateTime> _recentPacketTimes = new();
    private long _totalPackets;
    private long _totalBytes;
    private DateTime _captureStartedAt = DateTime.UtcNow;

    public bool IsCapturing => _activeEngine?.IsCapturing == true;
    public int BufferCount => _buffer.Count;
    public int BufferCapacity => _buffer.Capacity;

    public event EventHandler<PacketFrame>? PacketReceived;

    public ScoutManager()
    {
        _rawEngine = new RawSocketCaptureEngine();
        _ethernetEngine = new EthernetCaptureEngine();
        _rawEngine.PacketReceived += OnPacketCaptured;
        _ethernetEngine.PacketReceived += OnPacketCaptured;
    }

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices()
    {
        return GetAvailableDevices(PacketCaptureMode.RawIpv4);
    }

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices(PacketCaptureMode mode) => mode switch
    {
        PacketCaptureMode.RawIpv4 => _rawEngine.GetAvailableDevices(),
        PacketCaptureMode.Ethernet => _ethernetEngine.GetAvailableDevices(),
        _ => Array.Empty<NetworkDeviceDescriptor>()
    };

    public async Task StartCaptureAsync(string deviceId, CancellationToken cancellationToken = default)
        => await StartCaptureAsync(deviceId, PacketCaptureMode.RawIpv4, cancellationToken);

    public async Task StartCaptureAsync(string deviceId, PacketCaptureMode mode, CancellationToken cancellationToken = default)
    {
        if (IsCapturing) await StopCaptureAsync();
        _activeEngine = mode == PacketCaptureMode.Ethernet ? _ethernetEngine : _rawEngine;
        _captureStartedAt = DateTime.UtcNow;
        AppLogger.Info("ScoutManager", $"Starting {mode} packet capture on adapter: {deviceId}");
        try { await _activeEngine.StartCaptureAsync(deviceId, mode, cancellationToken); }
        catch { _activeEngine = null; throw; }
    }

    public async Task StopCaptureAsync()
    {
        AppLogger.Info("ScoutManager", "Stopping packet capture.");
        var engine = _activeEngine;
        if (engine != null) await engine.StopCaptureAsync();
        _activeEngine = null;
    }

    public void ClearBuffer()
    {
        _buffer.Clear();
        Interlocked.Exchange(ref _totalPackets, 0);
        Interlocked.Exchange(ref _totalBytes, 0);
        while (_recentPacketTimes.TryDequeue(out _)) { }
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
        var cutoff = DateTime.UtcNow.AddSeconds(-5);
        while (_recentPacketTimes.TryPeek(out var timestamp) && timestamp < cutoff) _recentPacketTimes.TryDequeue(out _);
        var pps = _recentPacketTimes.Count / 5d;

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
        _recentPacketTimes.Enqueue(DateTime.UtcNow);

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
        _rawEngine.PacketReceived -= OnPacketCaptured;
        _ethernetEngine.PacketReceived -= OnPacketCaptured;
        _rawEngine.Dispose();
        _ethernetEngine.Dispose();
    }
}
