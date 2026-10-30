using System.Text;
using Upuaut.Core.Models;

namespace Upuaut.Scout.Services;

/// <summary>Reassembles captured TCP payload segments per direction and marks sequence gaps.</summary>
public static class TcpStreamReassembler
{
    public static string Render(PacketConversation conversation)
    {
        if (conversation.Protocol != NetworkProtocol.TCP) return "Follow stream is available for TCP conversations.";
        var output = new StringBuilder();
        foreach (var direction in conversation.Frames.GroupBy(f => (f.SourceIp, f.SourcePort)))
        {
            var frames = direction.Where(f => f.RawData is { Length: > 0 } && f.TransportPayloadOffset is { } p && p < f.RawData.Length && f.TcpSequenceNumber.HasValue)
                .OrderBy(f => f.Timestamp).ToList();
            output.AppendLine($"{direction.Key.SourceIp}:{direction.Key.SourcePort} → {frames.FirstOrDefault()?.DestinationIp}:{frames.FirstOrDefault()?.DestinationPort}");
            if (frames.Count == 0) { output.AppendLine("No captured payload bytes in this direction."); continue; }
            var baseSequence = frames[0].TcpSequenceNumber!.Value + ((frames[0].TcpFlags & 0x02) != 0 ? 1u : 0u);
            var segments = frames.Select(f =>
            {
                var sequence = f.TcpSequenceNumber!.Value + ((f.TcpFlags & 0x02) != 0 ? 1u : 0u);
                var offset = unchecked((int)(sequence - baseSequence));
                var raw = f.RawData!; var start = f.TransportPayloadOffset!.Value;
                return (Offset: offset, Data: raw.AsSpan(start, Math.Min(raw.Length - start, 1024 * 1024)).ToArray());
            }).Where(s => s.Data.Length > 0).OrderBy(s => s.Offset).ToList();
            var assembled = new List<byte>(); var cursor = 0;
            foreach (var segment in segments)
            {
                if (segment.Offset > cursor) { output.AppendLine($"[capture gap: {segment.Offset - cursor} byte(s)]"); cursor = segment.Offset; }
                var overlap = Math.Max(0, cursor - segment.Offset);
                if (overlap >= segment.Data.Length) continue;
                assembled.AddRange(segment.Data.AsSpan(overlap).ToArray()); cursor += segment.Data.Length - overlap;
                if (assembled.Count >= 1024 * 1024) break;
            }
            output.AppendLine(Hex(assembled.ToArray())); output.AppendLine();
        }
        return output.ToString();
    }

    private static string Hex(byte[] data)
    {
        var text = new StringBuilder();
        for (var i = 0; i < data.Length; i += 16)
        {
            text.Append(i.ToString("X6")).Append("  ");
            for (var j = 0; j < 16; j++) text.Append(i + j < data.Length ? data[i + j].ToString("X2") + " " : "   ");
            text.Append(" | "); for (var j = 0; j < 16 && i + j < data.Length; j++) text.Append(data[i + j] is >= 32 and <= 126 ? (char)data[i + j] : '.'); text.AppendLine();
        }
        return text.ToString();
    }
}
