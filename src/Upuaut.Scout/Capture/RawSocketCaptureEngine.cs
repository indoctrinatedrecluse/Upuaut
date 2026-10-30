using System.Buffers;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Upuaut.Core.Diagnostics;
using Upuaut.Core.Interfaces;
using Upuaut.Core.Models;
using Upuaut.Scout.Parsers;

namespace Upuaut.Scout.Capture;

/// <summary>
/// Driverless Windows native raw socket packet capture engine.
/// Utilizes SIO_RCVALL to sniff all inbound/outbound IPv4 traffic on the bound network adapter
/// without requiring third-party kernel drivers like Npcap or WinPcap.
/// </summary>
public class RawSocketCaptureEngine : ICaptureEngine, IDisposable
{
    private Socket? _socket;
    private CancellationTokenSource? _cts;
    private Task? _receiveTask;
    private long _frameCounter;
    private bool _isCapturing;
    private readonly object _lock = new();
    private CancellationTokenRegistration _cancellationRegistration;
    private long _receivedPacketCount, _rejectedPacketCount, _receiveErrorCount;
    public long ReceivedPacketCount => Interlocked.Read(ref _receivedPacketCount);
    public long RejectedPacketCount => Interlocked.Read(ref _rejectedPacketCount);
    public long ReceiveErrorCount => Interlocked.Read(ref _receiveErrorCount);

    public bool IsCapturing => _isCapturing;
    public event EventHandler<PacketFrame>? PacketReceived;

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices()
    {
        var devices = new List<NetworkDeviceDescriptor>();

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var iface in interfaces)
            {
                if (iface.OperationalStatus != OperationalStatus.Up) continue;
                if (iface.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var ipProps = iface.GetIPProperties();
                foreach (var ipv4Address in ipProps.UnicastAddresses
                    .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address.Address) && !address.Address.Equals(IPAddress.Any))
                    .Select(address => address.Address)
                    .Distinct())
                {
                    devices.Add(new NetworkDeviceDescriptor(
                        Id: ipv4Address.ToString(),
                        Name: iface.Name,
                        Description: $"{iface.Description} | {iface.NetworkInterfaceType} | {ipv4Address}",
                        IpAddress: ipv4Address.ToString()));
                }
            }
        }
        catch (Exception ex)
        {
            AppLogger.Error("RawSocketCapture", "Failed enumerating network interfaces", ex);
        }

        return devices;
    }

    public Task StartCaptureAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
        {
            if (_isCapturing)
            {
                AppLogger.Warning("RawSocketCapture", "Capture is already active.");
                return Task.CompletedTask;
            }

            if (_receiveTask?.IsCompleted == true)
            {
                _cancellationRegistration.Dispose();
                _cts?.Dispose(); _cts = null; _receiveTask = null;
            }

            if (!IPAddress.TryParse(deviceId, out var bindIp))
            {
                var matches = GetAvailableDevices().Where(device =>
                    device.Id.Equals(deviceId, StringComparison.OrdinalIgnoreCase) ||
                    device.Name.Equals(deviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (matches.Length != 1 || !IPAddress.TryParse(matches[0].IpAddress, out bindIp))
                    throw new InvalidOperationException(matches.Length > 1
                        ? $"Adapter name '{deviceId}' has multiple IPv4 addresses. Select a specific address from the adapter list."
                        : $"Cannot resolve a current IPv4 address for adapter '{deviceId}'. Refresh the adapter list and select an available address.");
            }

            AppLogger.Info("RawSocketCapture", $"Initializing Windows Native Raw Socket on {bindIp}...");
            Interlocked.Exchange(ref _receivedPacketCount, 0); Interlocked.Exchange(ref _rejectedPacketCount, 0); Interlocked.Exchange(ref _receiveErrorCount, 0);

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                _socket.Bind(new IPEndPoint(bindIp, 0));
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                // SIO_RCVALL ioctl code (0x98000001)
                byte[] inValue = new byte[] { 1, 0, 0, 0 }; // RCVALL_ON
                byte[] outValue = new byte[4];
                _socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);

                _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                _isCapturing = true;
                _receiveTask = Task.Run(() => ReceiveLoop(_socket, bindIp.ToString(), _cts.Token), CancellationToken.None);

                AppLogger.Info("RawSocketCapture", $"Native packet capture active on {bindIp}.");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
            {
                _isCapturing = false;
                _socket?.Dispose();
                _socket = null;
                AppLogger.Error("RawSocketCapture", "Administrator elevation required to open raw socket (SIO_RCVALL).", ex);
                throw new UnauthorizedAccessException("Raw packet sniffing requires running Upuaut as Administrator.", ex);
            }
            catch (Exception ex)
            {
                _isCapturing = false;
                _cts?.Cancel();
                _socket?.Dispose();
                _socket = null;
                AppLogger.Error("RawSocketCapture", $"Failed to start raw socket capture on {bindIp}: {ex.Message}", ex);
                throw;
            }
        }

        var registration = cancellationToken.Register(() => _ = StopCaptureAsync());
        lock (_lock)
        {
            if (_isCapturing) _cancellationRegistration = registration;
            else registration.Dispose();
        }

        return Task.CompletedTask;
    }

    public Task StartCaptureAsync(string deviceId, PacketCaptureMode mode, CancellationToken cancellationToken = default)
    {
        if (mode != PacketCaptureMode.RawIpv4) throw new NotSupportedException("Raw socket capture supports IPv4 mode only.");
        return StartCaptureAsync(deviceId, cancellationToken);
    }

    public IReadOnlyList<NetworkDeviceDescriptor> GetAvailableDevices(PacketCaptureMode mode) => GetAvailableDevices();

    public async Task StopCaptureAsync()
    {
        Task? receiveTask;
        CancellationTokenSource? cts;
        lock (_lock)
        {
            if (!_isCapturing && _receiveTask == null) return;

            _isCapturing = false;
            cts = _cts;
            receiveTask = _receiveTask;
            _cancellationRegistration.Dispose();
            try
            {
                cts?.Cancel();
                _socket?.Close();
                _socket?.Dispose();
                _socket = null;
            }
            catch (Exception ex)
            {
                AppLogger.Debug("RawSocketCapture", $"Error closing raw socket: {ex.Message}");
            }

            AppLogger.Info("RawSocketCapture", "Packet capture stopped.");
        }

        if (receiveTask != null)
        {
            try { await receiveTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        lock (_lock)
        {
            if (ReferenceEquals(_cts, cts))
            {
                _cts?.Dispose();
                _cts = null;
                _receiveTask = null;
            }
        }
    }

    private void ReceiveLoop(Socket socket, string ifaceName, CancellationToken token)
    {
        var pool = ArrayPool<byte>.Shared;
        byte[] buffer = pool.Rent(65536);

        try
        {
            while (!token.IsCancellationRequested && _isCapturing)
            {
                int bytesReceived;
                try
                {
                    bytesReceived = socket.Receive(buffer, 0, buffer.Length, SocketFlags.None);
                }
                catch (SocketException ex)
                {
                    if (_isCapturing) AppLogger.Warning("RawSocketCapture", $"Receive stopped: {ex.SocketErrorCode} {ex.Message}");
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (bytesReceived <= 0) continue;
                Interlocked.Increment(ref _receivedPacketCount);

                PacketFrame? frame;
                try { frame = PacketParser.ParseIPv4Packet(buffer, bytesReceived, Interlocked.Increment(ref _frameCounter), ifaceName); }
                catch (Exception ex) { Interlocked.Increment(ref _rejectedPacketCount); AppLogger.Debug("RawSocketCapture", $"Rejected packet after parse error: {ex.Message}"); continue; }

                if (frame != null)
                {
                    try
                    {
                        PacketReceived?.Invoke(this, frame);
                    }
                    catch
                    {
                        // Guard against subscriber errors
                    }
                }
                else Interlocked.Increment(ref _rejectedPacketCount);
            }
        }
        finally
        {
            pool.Return(buffer);
            if (!token.IsCancellationRequested)
            {
                Interlocked.Increment(ref _receiveErrorCount);
                AppLogger.Warning("RawSocketCapture", "The packet receive loop stopped unexpectedly.");
                lock (_lock)
                {
                    _isCapturing = false;
                    if (ReferenceEquals(_socket, socket)) { try { _socket?.Dispose(); } catch { } _socket = null; }
                }
            }
        }
    }

    public void Dispose()
    {
        StopCaptureAsync().GetAwaiter().GetResult();
        _cts?.Dispose();
    }
}
