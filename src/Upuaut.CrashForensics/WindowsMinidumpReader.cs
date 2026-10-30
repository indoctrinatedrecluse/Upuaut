using System.Buffers.Binary;
using System.Text;
using Upuaut.CrashForensics.Models;

namespace Upuaut.CrashForensics;

public sealed record WindowsMinidumpMetadata(
    DateTimeOffset? DumpTimestampUtc,
    string? Architecture,
    string? OperatingSystem,
    uint? ProcessId,
    CrashExceptionEvidence? Exception,
    IReadOnlyList<CrashModuleEvidence> Modules,
    IReadOnlyList<CrashThreadEvidence> Threads,
    IReadOnlyList<string> Warnings);

/// <summary>Reads bounded metadata streams from an untrusted Windows MDMP file without mapping its memory payload.</summary>
public static class WindowsMinidumpReader
{
    private const uint Signature = 0x504D444D; // MDMP
    private const int MaximumDirectoryEntries = 512;
    private const int MaximumModules = 4_096;
    private const int MaximumThreads = 4_096;
    private const int MaximumStringBytes = 16_384;
    private const uint ModuleListStream = 4;
    private const uint ExceptionStream = 6;
    private const uint SystemInfoStream = 7;
    private const uint MiscInfoStream = 15;
    private const uint ProcessIdFlag = 1;

    public static bool HasMinidumpSignature(ReadOnlySpan<byte> bytes) => bytes.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(bytes) == Signature;

    public static WindowsMinidumpMetadata Read(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) throw new InvalidDataException("The dump must be a readable, seekable file stream.");
        if (stream.Length < 32) throw new InvalidDataException("The dump is too short to contain a Windows minidump header.");
        var warnings = new List<string>();
        if (ReadUInt32(stream, 0) != Signature) throw new InvalidDataException("The file does not have the Windows MDMP signature.");

        var numberOfStreams = ReadUInt32(stream, 8);
        var directoryRva = ReadUInt32(stream, 12);
        if (numberOfStreams > MaximumDirectoryEntries)
        {
            warnings.Add($"The dump declares {numberOfStreams:N0} streams; only the first {MaximumDirectoryEntries:N0} are inspected.");
            numberOfStreams = MaximumDirectoryEntries;
        }
        EnsureRange(stream, directoryRva, checked((long)numberOfStreams * 12), "stream directory");
        var streams = new Dictionary<uint, (uint Size, uint Rva)>();
        for (var index = 0; index < numberOfStreams; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var offset = checked((long)directoryRva + index * 12L);
            var type = ReadUInt32(stream, offset);
            var size = ReadUInt32(stream, offset + 4);
            var rva = ReadUInt32(stream, offset + 8);
            if (size > 0 && !IsRangeInside(stream, rva, size))
            {
                warnings.Add($"Stream {type} points outside the file and was skipped.");
                continue;
            }
            if (!streams.TryAdd(type, (size, rva))) warnings.Add($"Duplicate stream {type} was ignored.");
        }

        var dumpTime = ReadUInt32(stream, 20);
        DateTimeOffset? dumpTimestamp = dumpTime is > 0 and < 4_102_444_800
            ? DateTimeOffset.FromUnixTimeSeconds(dumpTime)
            : null;

        var architecture = (string?)null;
        var osVersion = (string?)null;
        if (streams.TryGetValue(SystemInfoStream, out var systemInfo) && systemInfo.Size >= 32)
        {
            var architectureCode = ReadUInt16(stream, systemInfo.Rva);
            architecture = architectureCode switch
            {
                0 => "x86",
                5 => "ARM",
                9 => "x64",
                12 => "ARM64",
                6 => "Intel Itanium",
                _ => $"Unknown architecture ({architectureCode})"
            };
            var major = ReadUInt32(stream, systemInfo.Rva + 8L);
            var minor = ReadUInt32(stream, systemInfo.Rva + 12L);
            var build = ReadUInt32(stream, systemInfo.Rva + 16L);
            var platform = ReadUInt32(stream, systemInfo.Rva + 20L);
            var servicePackRva = ReadUInt32(stream, systemInfo.Rva + 24L);
            var servicePack = ReadMinidumpString(stream, servicePackRva);
            var platformName = platform switch { 2 => "Windows NT", 1 => "Win32s", 0 => "Win32s/unknown", _ => $"Platform {platform}" };
            osVersion = $"{platformName} {major}.{minor}.{build}" + (string.IsNullOrWhiteSpace(servicePack) ? string.Empty : $" ({servicePack})");
        }
        else warnings.Add("The dump has no complete system information stream.");

        var processId = ReadProcessId(stream, streams, warnings);
        var exception = ReadException(stream, streams, warnings);
        var modules = ReadModules(stream, streams, warnings, cancellationToken);
        var threads = ReadThreads(stream, streams, warnings, cancellationToken);
        return new(dumpTimestamp, architecture, osVersion, processId, exception, modules, threads, warnings);
    }

    private static uint? ReadProcessId(Stream stream, IReadOnlyDictionary<uint, (uint Size, uint Rva)> streams, List<string> warnings)
    {
        if (!streams.TryGetValue(MiscInfoStream, out var misc) || misc.Size < 12) return null;
        var size = ReadUInt32(stream, misc.Rva);
        var flags = ReadUInt32(stream, misc.Rva + 4L);
        if ((flags & ProcessIdFlag) == 0 || size < 12 || size > misc.Size) return null;
        return ReadUInt32(stream, misc.Rva + 8L);
    }

    private static CrashExceptionEvidence? ReadException(Stream stream, IReadOnlyDictionary<uint, (uint Size, uint Rva)> streams, List<string> warnings)
    {
        if (!streams.TryGetValue(ExceptionStream, out var exception)) return null;
        if (exception.Size < 168)
        {
            warnings.Add("The exception stream is truncated; exception details were skipped.");
            return null;
        }
        var threadId = ReadUInt32(stream, exception.Rva);
        var record = exception.Rva + 8L;
        var code = ReadUInt32(stream, record);
        var address = ReadUInt64(stream, record + 16);
        var count = Math.Min(ReadUInt32(stream, record + 32), 15);
        var values = new ulong[count];
        for (var index = 0; index < count; index++) values[index] = ReadUInt64(stream, record + 40 + index * 8L);
        return new(code, address, threadId, values);
    }

    private static IReadOnlyList<CrashModuleEvidence> ReadModules(Stream stream, IReadOnlyDictionary<uint, (uint Size, uint Rva)> streams, List<string> warnings, CancellationToken cancellationToken)
    {
        if (!streams.TryGetValue(ModuleListStream, out var modulesStream) || modulesStream.Size < 4) return [];
        var declaredCount = ReadUInt32(stream, modulesStream.Rva);
        var available = (modulesStream.Size - 4) / 108;
        var count = (int)Math.Min(Math.Min(declaredCount, available), MaximumModules);
        if (count < declaredCount) warnings.Add($"The module list was capped or truncated ({count:N0} of {declaredCount:N0} entries inspected).");
        var result = new List<CrashModuleEvidence>(count);
        for (var index = 0; index < count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var offset = checked((long)modulesStream.Rva + 4 + index * 108L);
            var baseAddress = ReadUInt64(stream, offset);
            var imageSize = ReadUInt32(stream, offset + 8);
            var timestamp = ReadUInt32(stream, offset + 16);
            var nameRva = ReadUInt32(stream, offset + 20);
            var name = ReadMinidumpString(stream, nameRva);
            result.Add(new(string.IsNullOrWhiteSpace(name) ? $"Module {index + 1}" : name, baseAddress, imageSize, timestamp));
        }
        return result;
    }

    private static IReadOnlyList<CrashThreadEvidence> ReadThreads(Stream stream, IReadOnlyDictionary<uint, (uint Size, uint Rva)> streams, List<string> warnings, CancellationToken cancellationToken)
    {
        if (!streams.TryGetValue(3, out var threadsStream) || threadsStream.Size < 4) return [];
        var declaredCount = ReadUInt32(stream, threadsStream.Rva);
        var available = (threadsStream.Size - 4) / 48;
        var count = (int)Math.Min(Math.Min(declaredCount, available), MaximumThreads);
        if (count < declaredCount) warnings.Add($"The thread list was capped or truncated ({count:N0} of {declaredCount:N0} entries inspected).");
        var result = new List<CrashThreadEvidence>(count);
        for (var index = 0; index < count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var offset = checked((long)threadsStream.Rva + 4 + index * 48L);
            var id = ReadUInt32(stream, offset);
            var tebAddress = ReadUInt64(stream, offset + 16);
            var stackStart = ReadUInt64(stream, offset + 24);
            var stackSize = ReadUInt32(stream, offset + 32);
            result.Add(new(id, tebAddress, stackStart, stackSize));
        }
        return result;
    }

    private static string? ReadMinidumpString(Stream stream, uint rva)
    {
        if (rva == 0 || !IsRangeInside(stream, rva, 4)) return null;
        var byteCount = ReadUInt32(stream, rva);
        if (byteCount is 0 or > MaximumStringBytes || (byteCount & 1) != 0 || !IsRangeInside(stream, (long)rva + 4, byteCount)) return null;
        var bytes = ReadBytes(stream, (long)rva + 4, (int)byteCount);
        return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
    }

    private static byte[] ReadBytes(Stream stream, long offset, int count)
    {
        EnsureRange(stream, offset, count, "data");
        stream.Position = offset;
        var bytes = new byte[count];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static ushort ReadUInt16(Stream stream, long offset) => BinaryPrimitives.ReadUInt16LittleEndian(ReadBytes(stream, offset, 2));
    private static uint ReadUInt32(Stream stream, long offset) => BinaryPrimitives.ReadUInt32LittleEndian(ReadBytes(stream, offset, 4));
    private static ulong ReadUInt64(Stream stream, long offset) => BinaryPrimitives.ReadUInt64LittleEndian(ReadBytes(stream, offset, 8));

    private static bool IsRangeInside(Stream stream, long offset, long length) => offset >= 0 && length >= 0 && offset <= stream.Length && length <= stream.Length - offset;

    private static void EnsureRange(Stream stream, long offset, long length, string label)
    {
        if (!IsRangeInside(stream, offset, length)) throw new InvalidDataException($"The dump's {label} range is outside the file.");
    }
}
