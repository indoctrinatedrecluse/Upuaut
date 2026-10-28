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
                var ipv4Addr = ipProps.UnicastAddresses
                    .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

                if (ipv4Addr != null)
                {
                    devices.Add(new NetworkDeviceDescriptor(
                        Id: ipv4Addr.Address.ToString(),
                        Name: iface.Name,
                        Description: $"{iface.Description} ({ipv4Addr.Address})",
                        IpAddress: ipv4Addr.Address.ToString()));
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
        lock (_lock)
        {
            if (_isCapturing)
            {
                AppLogger.Warning("RawSocketCapture", "Capture is already active.");
                return Task.CompletedTask;
            }

            if (!IPAddress.TryParse(deviceId, out var bindIp))
            {
                // If deviceId wasn't an IP, find first available device
                var devices = GetAvailableDevices();
                var selected = devices.FirstOrDefault(d => d.Id == deviceId || d.Name == deviceId) ?? devices.FirstOrDefault();
                if (selected == null || !IPAddress.TryParse(selected.IpAddress, out bindIp))
                {
                    throw new InvalidOperationException($"Cannot resolve valid IPv4 address for adapter '{deviceId}'.");
                }
            }

            AppLogger.Info("RawSocketCapture", $"Initializing Windows Native Raw Socket on {bindIp}...");

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                _socket.Bind(new IPEndPoint(bindIp, 0));
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                // SIO_RCVALL ioctl code (0x98000001)
                byte[] inValue = new byte[] { 1, 0, 0, 0 }; // RCVALL_ON
                byte[] outValue = new byte[4];
                _socket.IOControl(IOControlCode.ReceiveAll, inValue, outValue);

                _cts = new CancellationTokenSource();
                _isCapturing = true;
                _receiveTask = Task.Run(() => ReceiveLoop(_socket, bindIp.ToString(), _cts.Token));

                AppLogger.Info("RawSocketCapture", $"Native packet capture active on {bindIp}.");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
            {
                _isCapturing = false;
                AppLogger.Error("RawSocketCapture", "Administrator elevation required to open raw socket (SIO_RCVALL).", ex);
                throw new UnauthorizedAccessException("Raw packet sniffing requires running Upuaut as Administrator.", ex);
            }
            catch (Exception ex)
            {
                _isCapturing = false;
                AppLogger.Error("RawSocketCapture", $"Failed to start raw socket capture on {bindIp}: {ex.Message}", ex);
                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task StopCaptureAsync()
    {
        lock (_lock)
        {
            if (!_isCapturing) return Task.CompletedTask;

            _isCapturing = false;
            try
            {
                _cts?.Cancel();
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

        return Task.CompletedTask;
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
                catch (SocketException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (bytesReceived <= 0) continue;

                var frameIndex = Interlocked.Increment(ref _frameCounter);
                var frame = PacketParser.ParseIPv4Packet(buffer, bytesReceived, frameIndex, ifaceName);

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
            }
        }
        finally
        {
            pool.Return(buffer);
        }
    }

    public void Dispose()
    {
        StopCaptureAsync().GetAwaiter().GetResult();
        _cts?.Dispose();
    }
}
