using System.Buffers.Binary;
using Upuaut.Core.Models;
using Upuaut.Scout.Parsers;

namespace Upuaut.Scout.Services;

/// <summary>Minimal PCAPNG reader/writer for Ethernet and raw IPv4 packet blocks.</summary>
public static class PcapNgFile
{
    private sealed record InterfaceInfo(ushort LinkType, int TimestampResolution, string? Name);

    public static void Write(string path, IEnumerable<PacketFrame> frames)
    {
        var packets = frames.Where(frame => frame.RawData is { Length: > 0 }).ToList();
        using var stream = File.Create(path);
        WriteBlock(stream, 0x0A0D0D0A, Build(0x1A2B3C4D, 1, 0));
        var interfaceKeys = packets.Select(f => (Link: f.CaptureLayer.Equals("Ethernet", StringComparison.OrdinalIgnoreCase) ? (ushort)1 : (ushort)101, Name: f.InterfaceName ?? string.Empty)).Distinct().ToArray();
        var interfaceMap = new Dictionary<(ushort Link, string Name), uint>();
        for (var i = 0; i < interfaceKeys.Length; i++)
        {
            interfaceMap[interfaceKeys[i]] = (uint)i;
            using var body = new MemoryStream(); using var writer = new BinaryWriter(body);
            writer.Write(interfaceKeys[i].Link); writer.Write((ushort)0); writer.Write(262144u);
            if (!string.IsNullOrWhiteSpace(interfaceKeys[i].Name))
            {
                var name = System.Text.Encoding.UTF8.GetBytes(interfaceKeys[i].Name);
                if (name.Length > 255) name = name[..255];
                writer.Write((ushort)2); writer.Write((ushort)name.Length); writer.Write(name); Pad(body, (4 - name.Length % 4) % 4);
            }
            writer.Write((ushort)9); writer.Write((ushort)1); writer.Write((byte)6); Pad(body, 3);
            writer.Write((ushort)0); writer.Write((ushort)0);
            WriteBlock(stream, 1, body.ToArray());
        }
        foreach (var frame in packets)
        {
            var raw = frame.RawData!;
            var link = frame.CaptureLayer.Equals("Ethernet", StringComparison.OrdinalIgnoreCase) ? (ushort)1 : (ushort)101;
            var micros = Math.Max(0, (frame.Timestamp.ToUniversalTime().Ticks - DateTime.UnixEpoch.Ticks) / 10);
            using var body = new MemoryStream(); using var writer = new BinaryWriter(body);
            writer.Write(interfaceMap[(link, frame.InterfaceName ?? string.Empty)]); writer.Write((uint)(micros >> 32)); writer.Write((uint)micros);
            writer.Write((uint)raw.Length); writer.Write((uint)raw.Length); writer.Write(raw); Pad(body, (4 - raw.Length % 4) % 4);
            writer.Write((ushort)0); writer.Write((ushort)0);
            WriteBlock(stream, 6, body.ToArray());
        }
    }

    public static IReadOnlyList<PacketFrame> Read(string path, int maxFrames = 250_000)
    {
        if (maxFrames < 1) throw new ArgumentOutOfRangeException(nameof(maxFrames));
        using var stream = File.OpenRead(path); var result = new List<PacketFrame>(); var interfaces = new List<InterfaceInfo>(); var little = true; long index = 0;
        while (stream.Position + 12 <= stream.Length)
        {
            using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, true);
            var typeBytes = reader.ReadBytes(4); if (typeBytes.Length != 4) break;
            var type = little ? BinaryPrimitives.ReadUInt32LittleEndian(typeBytes) : BinaryPrimitives.ReadUInt32BigEndian(typeBytes);
            var lengthBytes = reader.ReadBytes(4); if (lengthBytes.Length != 4) break;
            if (type == 0x0A0D0D0A)
            {
                var sectionStart = stream.Position - 8;
                var bom = reader.ReadBytes(4);
                little = bom.SequenceEqual(new byte[] { 0x4D, 0x3C, 0x2B, 0x1A });
                if (!little && !bom.SequenceEqual(new byte[] { 0x1A, 0x2B, 0x3C, 0x4D })) throw new InvalidDataException("Invalid PCAPNG byte-order marker.");
                var sectionLength = ReadU32(lengthBytes, 0, little);
                if (sectionLength < 28 || sectionLength > stream.Length - sectionStart) throw new InvalidDataException("Invalid PCAPNG section length.");
                stream.Position = sectionStart + sectionLength - 4;
                if (ReadU32(reader.ReadBytes(4), 0, little) != sectionLength) throw new InvalidDataException("PCAPNG section length trailer mismatch.");
                interfaces.Clear(); continue;
            }
            var blockLength = ReadU32(lengthBytes, 0, little);
            if (blockLength < 12 || blockLength > stream.Length - (stream.Position - 8) || blockLength > 64 * 1024 * 1024) throw new InvalidDataException("Invalid or oversized PCAPNG block.");
            var bodyLength = checked((int)blockLength - 12); var body = reader.ReadBytes(bodyLength); if (body.Length != bodyLength) break;
            var trailer = reader.ReadBytes(4); if (trailer.Length != 4 || ReadU32(trailer, 0, little) != blockLength) throw new InvalidDataException("PCAPNG block length trailer mismatch.");
            if (type == 1 && body.Length >= 8)
            {
                var link = ReadU16(body, 0, little); var resolution = 6; string? interfaceName = null;
                for (var p = 8; p + 4 <= body.Length;)
                {
                    var code = ReadU16(body, p, little); var len = ReadU16(body, p + 2, little); p += 4;
                    if (code == 0) break;
                    if (p + len > body.Length) break;
                    if (code == 9 && len == 1) resolution = body[p];
                    if (code == 2) interfaceName = System.Text.Encoding.UTF8.GetString(body, p, len);
                    p += len + ((4 - len % 4) % 4);
                }
                interfaces.Add(new InterfaceInfo(link, resolution, interfaceName));
            }
            else if (type == 6 && body.Length >= 20)
            {
                if (result.Count >= maxFrames) break;
                var id = ReadU32(body, 0, little); if (id >= interfaces.Count) continue;
                var info = interfaces[(int)id]; var high = ReadU32(body, 4, little); var low = ReadU32(body, 8, little);
                var cap = ReadU32(body, 12, little); if (cap > body.Length - 20 || cap > 16 * 1024 * 1024) continue;
                var original = ReadU32(body, 16, little); if (cap > original) continue;
                var data = body.AsSpan(20, (int)cap).ToArray(); var rawTimestamp = ((ulong)high << 32) | low;
                var resolution = info.TimestampResolution;
                var seconds = (resolution & 0x80) == 0 ? rawTimestamp / Math.Pow(10, resolution) : rawTimestamp / Math.Pow(2, resolution & 0x7F);
                if (!double.IsFinite(seconds) || seconds > 253_402_300_799d) continue;
                var timestamp = DateTime.UnixEpoch.AddSeconds(seconds);
                var frame = info.LinkType switch
                {
                    1 => PacketParser.ParseEthernetFrame(data, data.Length, ++index),
                    101 when data.Length > 0 && (data[0] >> 4) == 4 => PacketParser.ParseIPv4Packet(data, data.Length, ++index),
                    101 when data.Length > 0 && (data[0] >> 4) == 6 => PacketParser.ParseIPv6Packet(data, data.Length, ++index),
                    _ => null
                };
                if (frame is not null) result.Add(frame with { Timestamp = timestamp, InterfaceName = info.Name, ProcessId = null, ProcessName = null });
            }
        }
        return result;
    }

    private static void WriteBlock(Stream stream, uint type, byte[] body)
    {
        var length = checked((uint)(body.Length + 12)); using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, true);
        writer.Write(type); writer.Write(length); writer.Write(body); writer.Write(length);
    }
    private static byte[] Build(uint magic, ushort major, ushort minor)
    { using var s = new MemoryStream(); using var w = new BinaryWriter(s); w.Write(magic); w.Write(major); w.Write(minor); w.Write(-1L); return s.ToArray(); }
    private static void Pad(Stream stream, int count) { for (var i = 0; i < count; i++) stream.WriteByte(0); }
    private static ushort ReadU16(byte[] b, int p, bool little) => little ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p, 2)) : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(p, 2));
    private static uint ReadU32(byte[] b, int p, bool little) => little ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p, 4)) : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(p, 4));
}
