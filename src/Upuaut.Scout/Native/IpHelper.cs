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
    private const int AF_INET = 2;   // IPv4
    private const int AF_INET6 = 23; // IPv6

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

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public uint state;
        public uint owningPid;

        public ushort LocalPort => (ushort)((localPort1 << 8) + localPort2);
        public ushort RemotePort => (ushort)((remotePort1 << 8) + remotePort2);
        public IPAddress LocalIp => new(localAddr);
        public IPAddress RemoteIp => new(remoteAddr);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
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

    private const uint NO_ERROR = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    private record struct PidCacheEntry(string Name, DateTime CachedAt);
    private static readonly ConcurrentDictionary<int, PidCacheEntry> _pidNameCache = new();
    private static readonly TimeSpan PidCacheDuration = TimeSpan.FromSeconds(30);
    private const int MaxPidCacheEntries = 2048;

    private static volatile Dictionary<string, (int Pid, string Name)> _endpointSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private static DateTime _lastFullScan = DateTime.MinValue;
    private static readonly TimeSpan CacheExpiry = TimeSpan.FromSeconds(2.5);
    private static readonly object _refreshLock = new();

    /// <summary>
    /// Resolves the local or remote port to the owning Windows Process ID and Process Name.
    /// Thread-safe and lock-free across high-throughput packet processing threads.
    /// </summary>
    public static (int? ProcessId, string? ProcessName) ResolveProcess(string sourceIp, int sourcePort, string destinationIp, int destinationPort)
    {
        RefreshTablesIfStale();

        var snapshot = _endpointSnapshot;
        if (snapshot.TryGetValue(Key(sourceIp, sourcePort, destinationIp, destinationPort), out var match) ||
            snapshot.TryGetValue(Key(destinationIp, destinationPort, sourceIp, sourcePort), out match) ||
            snapshot.TryGetValue(Key(sourceIp, sourcePort, "0.0.0.0", 0), out match) ||
            snapshot.TryGetValue(Key(destinationIp, destinationPort, "0.0.0.0", 0), out match) ||
            snapshot.TryGetValue(Key("0.0.0.0", sourcePort, "0.0.0.0", 0), out match) ||
            snapshot.TryGetValue(Key("0.0.0.0", destinationPort, "0.0.0.0", 0), out match) ||
            snapshot.TryGetValue(Key(sourceIp, sourcePort, "::", 0), out match) ||
            snapshot.TryGetValue(Key(destinationIp, destinationPort, "::", 0), out match) ||
            snapshot.TryGetValue(Key("::", sourcePort, "::", 0), out match) ||
            snapshot.TryGetValue(Key("::", destinationPort, "::", 0), out match))
        {
            return (match.Pid, match.Name);
        }

        return (null, null);
    }

    private static string Key(string localIp, int localPort, string remoteIp, int remotePort) => $"{localIp}:{localPort}|{remoteIp}:{remotePort}";

    private static void RefreshTablesIfStale()
    {
        if (DateTime.UtcNow - _lastFullScan < CacheExpiry) return;

        // Non-blocking try-enter ensures only one thread refreshes while others continue reading current snapshot
        if (!Monitor.TryEnter(_refreshLock)) return;
        try
        {
            if (DateTime.UtcNow - _lastFullScan < CacheExpiry) return;

            var newCache = new Dictionary<string, (int Pid, string Name)>(StringComparer.OrdinalIgnoreCase);
            RefreshTcpTable(newCache);
            RefreshUdpTable(newCache);
            RefreshTcp6Table(newCache);
            RefreshUdp6Table(newCache);

            _endpointSnapshot = newCache;
            _lastFullScan = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            AppLogger.Debug("IpHelper", $"Error querying endpoint tables: {ex.Message}");
        }
        finally
        {
            Monitor.Exit(_refreshLock);
        }
    }

    private static void RefreshTcpTable(Dictionary<string, (int Pid, string Name)> table)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return;

        int attempts = 0;
        IntPtr tcpTablePtr = IntPtr.Zero;
        try
        {
            uint ret = ERROR_INSUFFICIENT_BUFFER;
            while (ret == ERROR_INSUFFICIENT_BUFFER && attempts++ < 3)
            {
                if (tcpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                    tcpTablePtr = IntPtr.Zero;
                }
                tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
                ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            }

            if (ret != NO_ERROR || tcpTablePtr == IntPtr.Zero) return;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                var pid = (int)row.owningPid;
                if (pid > 0)
                {
                    var procName = GetProcessName(pid);
                    table[Key(row.LocalIp.ToString(), row.LocalPort, row.RemoteIp.ToString(), row.RemotePort)] = (pid, procName);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            if (tcpTablePtr != IntPtr.Zero) Marshal.FreeHGlobal(tcpTablePtr);
        }
    }

    private static void RefreshUdpTable(Dictionary<string, (int Pid, string Name)> table)
    {
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
        if (bufferSize <= 0) return;

        int attempts = 0;
        IntPtr udpTablePtr = IntPtr.Zero;
        try
        {
            uint ret = ERROR_INSUFFICIENT_BUFFER;
            while (ret == ERROR_INSUFFICIENT_BUFFER && attempts++ < 3)
            {
                if (udpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                    udpTablePtr = IntPtr.Zero;
                }
                udpTablePtr = Marshal.AllocHGlobal(bufferSize);
                ret = GetExtendedUdpTable(udpTablePtr, ref bufferSize, false, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            }

            if (ret != NO_ERROR || udpTablePtr == IntPtr.Zero) return;

            int rowCount = Marshal.ReadInt32(udpTablePtr);
            IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                var pid = (int)row.owningPid;
                if (pid > 0)
                {
                    var procName = GetProcessName(pid);
                    table[Key(row.LocalIp.ToString(), row.LocalPort, "0.0.0.0", 0)] = (pid, procName);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            if (udpTablePtr != IntPtr.Zero) Marshal.FreeHGlobal(udpTablePtr);
        }
    }

    private static void RefreshTcp6Table(Dictionary<string, (int Pid, string Name)> table)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return;

        int attempts = 0;
        IntPtr tcpTablePtr = IntPtr.Zero;
        try
        {
            uint ret = ERROR_INSUFFICIENT_BUFFER;
            while (ret == ERROR_INSUFFICIENT_BUFFER && attempts++ < 3)
            {
                if (tcpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                    tcpTablePtr = IntPtr.Zero;
                }
                tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
                ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            }

            if (ret != NO_ERROR || tcpTablePtr == IntPtr.Zero) return;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                var pid = (int)row.owningPid;
                if (pid > 0)
                {
                    var procName = GetProcessName(pid);
                    table[Key(row.LocalIp.ToString(), row.LocalPort, row.RemoteIp.ToString(), row.RemotePort)] = (pid, procName);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        catch (Exception ex)
        {
            AppLogger.Debug("IpHelper", $"Error reading TCP IPv6 table: {ex.Message}");
        }
        finally
        {
            if (tcpTablePtr != IntPtr.Zero) Marshal.FreeHGlobal(tcpTablePtr);
        }
    }

    private static void RefreshUdp6Table(Dictionary<string, (int Pid, string Name)> table)
    {
        int bufferSize = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, false, AF_INET6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
        if (bufferSize <= 0) return;

        int attempts = 0;
        IntPtr udpTablePtr = IntPtr.Zero;
        try
        {
            uint ret = ERROR_INSUFFICIENT_BUFFER;
            while (ret == ERROR_INSUFFICIENT_BUFFER && attempts++ < 3)
            {
                if (udpTablePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                    udpTablePtr = IntPtr.Zero;
                }
                udpTablePtr = Marshal.AllocHGlobal(bufferSize);
                ret = GetExtendedUdpTable(udpTablePtr, ref bufferSize, false, AF_INET6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
            }

            if (ret != NO_ERROR || udpTablePtr == IntPtr.Zero) return;

            int rowCount = Marshal.ReadInt32(udpTablePtr);
            IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                var pid = (int)row.owningPid;
                if (pid > 0)
                {
                    var procName = GetProcessName(pid);
                    table[Key(row.LocalIp.ToString(), row.LocalPort, "::", 0)] = (pid, procName);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        catch (Exception ex)
        {
            AppLogger.Debug("IpHelper", $"Error reading UDP IPv6 table: {ex.Message}");
        }
        finally
        {
            if (udpTablePtr != IntPtr.Zero) Marshal.FreeHGlobal(udpTablePtr);
        }
    }

    private static string GetProcessName(int pid)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System";

        var now = DateTime.UtcNow;
        if (_pidNameCache.TryGetValue(pid, out var cached) && now - cached.CachedAt < PidCacheDuration)
        {
            return cached.Name;
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            var name = proc.ProcessName;

            if (_pidNameCache.Count > MaxPidCacheEntries)
            {
                _pidNameCache.Clear();
            }

            _pidNameCache[pid] = new PidCacheEntry(name, now);
            return name;
        }
        catch
        {
            return $"PID {pid}";
        }
    }
}
