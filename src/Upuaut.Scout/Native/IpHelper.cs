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

    // Cache of port -> (PID, ProcessName) with short expiration
    private static readonly ConcurrentDictionary<int, (int Pid, string Name, DateTime CachedAt)> _portCache = new();
    private static readonly ConcurrentDictionary<int, string> _pidNameCache = new();
    private static DateTime _lastFullScan = DateTime.MinValue;
    private static readonly TimeSpan CacheExpiry = TimeSpan.FromSeconds(2.5);

    /// <summary>
    /// Resolves the local or remote port to the owning Windows Process ID and Process Name.
    /// </summary>
    public static (int? ProcessId, string? ProcessName) ResolveProcess(int localPort, int remotePort)
    {
        RefreshTablesIfStale();

        // 1. Try local port match
        if (_portCache.TryGetValue(localPort, out var match) && match.Pid > 0)
        {
            return (match.Pid, match.Name);
        }

        // 2. Try remote port match (if local port was ephemeral and remote is local daemon)
        if (_portCache.TryGetValue(remotePort, out var remoteMatch) && remoteMatch.Pid > 0)
        {
            return (remoteMatch.Pid, remoteMatch.Name);
        }

        return (null, null);
    }

    private static void RefreshTablesIfStale()
    {
        if (DateTime.UtcNow - _lastFullScan < CacheExpiry)
        {
            return;
        }

        _lastFullScan = DateTime.UtcNow;

        try
        {
            RefreshTcpTable();
            RefreshUdpTable();
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
                    _portCache[row.LocalPort] = (pid, procName, now);
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
                    _portCache[row.LocalPort] = (pid, procName, now);
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
