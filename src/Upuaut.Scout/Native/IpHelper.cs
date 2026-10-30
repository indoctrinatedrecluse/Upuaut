using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Upuaut.Core.Diagnostics;

namespace Upuaut.Scout.Native;

/// <summary>
/// Native Windows IP Helper API interop for real-time Socket-to-Process attribution.
/// Queries active TCP and UDP endpoint tables to associate IP:Port 4-tuples with Process IDs and names.
/// </summary>
public static class IpHelper
{
    private const int AF_INET = 2; // IPv4

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    private enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint remoteAddr;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public uint owningPid;

        public ushort LocalPort => (ushort)((localPort1 << 8) + localPort2);
        public ushort RemotePort => (ushort)((remotePort1 << 8) + remotePort2);
        public IPAddress LocalIp => new(localAddr);
        public IPAddress RemoteIp => new(remoteAddr);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint owningPid;

        public ushort LocalPort => (ushort)((localPort1 << 8) + localPort2);
        public IPAddress LocalIp => new(localAddr);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        TCP_TABLE_CLASS tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        UDP_TABLE_CLASS tableClass,
        uint reserved = 0);

    private static readonly ConcurrentDictionary<string, (int Pid, string Name)> _endpointCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<int, string> _pidNameCache = new();
    private static DateTime _lastFullScan = DateTime.MinValue;
    private static readonly TimeSpan CacheExpiry = TimeSpan.FromSeconds(2.5);

    /// <summary>
    /// Resolves the local or remote port to the owning Windows Process ID and Process Name.
    /// </summary>
    public static (int? ProcessId, string? ProcessName) ResolveProcess(string sourceIp, int sourcePort, string destinationIp, int destinationPort)
    {
        RefreshTablesIfStale();
        if (_endpointCache.TryGetValue(Key(sourceIp, sourcePort, destinationIp, destinationPort), out var match) ||
            _endpointCache.TryGetValue(Key(destinationIp, destinationPort, sourceIp, sourcePort), out match) ||
            _endpointCache.TryGetValue(Key(sourceIp, sourcePort, "0.0.0.0", 0), out match) ||
            _endpointCache.TryGetValue(Key(destinationIp, destinationPort, "0.0.0.0", 0), out match) ||
            _endpointCache.TryGetValue(Key("0.0.0.0", sourcePort, "0.0.0.0", 0), out match) ||
            _endpointCache.TryGetValue(Key("0.0.0.0", destinationPort, "0.0.0.0", 0), out match))
            return (match.Pid, match.Name);
        return (null, null);
    }

    private static string Key(string localIp, int localPort, string remoteIp, int remotePort) => $"{localIp}:{localPort}|{remoteIp}:{remotePort}";

    private static void RefreshTablesIfStale()
    {
        if (DateTime.UtcNow - _lastFullScan < CacheExpiry)
        {
            return;
        }

        try
        {
            _endpointCache.Clear();
            RefreshTcpTable();
            RefreshUdpTable();
            _lastFullScan = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            AppLogger.Debug("IpHelper", $"Error querying endpoint tables: {ex.Message}");
        }
    }

    private static void RefreshTcpTable()
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

        if (bufferSize <= 0) return;

        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            if (ret != 0) return;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            var now = DateTime.UtcNow;

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                var pid = (int)row.owningPid;
                if (pid > 0)
                {
                    var procName = GetProcessName(pid);
                    _endpointCache[Key(row.LocalIp.ToString(), row.LocalPort, row.RemoteIp.ToString(), row.RemotePort)] = (pid, procName);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }
    }

    private static void RefreshUdpTable()
    {
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);

        if (bufferSize <= 0) return;

        IntPtr udpTablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedUdpTable(udpTablePtr, ref bufferSize, false, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            if (ret != 0) return;

            int rowCount = Marshal.ReadInt32(udpTablePtr);
            IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            var now = DateTime.UtcNow;

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                var pid = (int)row.owningPid;
                if (pid > 0)
                {
                    var procName = GetProcessName(pid);
                    _endpointCache[Key(row.LocalIp.ToString(), row.LocalPort, "0.0.0.0", 0)] = (pid, procName);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(udpTablePtr);
        }
    }

    private static string GetProcessName(int pid)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System";

        if (_pidNameCache.TryGetValue(pid, out var cached))
        {
            return cached;
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            var name = proc.ProcessName;
            _pidNameCache[pid] = name;
            return name;
        }
        catch
        {
            return $"PID {pid}";
        }
    }
}
