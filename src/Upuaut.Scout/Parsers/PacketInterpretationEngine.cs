using System.Buffers.Binary;
using System.Text;
using Upuaut.Core.Models;

namespace Upuaut.Scout.Parsers;

internal static class PacketInterpretationEngine
{
    public static PacketInterpretation Analyze(PacketFrame frame)
    {
        var category = "Network traffic";
        var headline = $"{frame.Protocol} exchange";
        var summary = "Protocol fields were decoded from this captured frame.";
        var tags = new List<string> { frame.Protocol.ToString().ToLowerInvariant() };
        var advice = new List<string>();
        var evidence = new List<EvidenceObservation>
        {
            new("Endpoints", $"{frame.SourceIp}:{frame.SourcePort?.ToString() ?? "—"} → {frame.DestinationIp}:{frame.DestinationPort?.ToString() ?? "—"}", "Addresses and ports decoded from the network and transport headers."),
            new("Frame length", $"{frame.TotalLength} bytes", "Captured frame length; link-layer padding may be included.")
        };
        if (frame.ProcessName is not null) evidence.Add(new("Process", frame.ProcessName, "Process attribution matched the endpoint tuple at capture time."));

        switch (frame.Protocol)
        {
            case NetworkProtocol.DNS:
                category = "Name resolution"; headline = frame.DnsQueryName is null ? "DNS message captured" : $"DNS lookup: {frame.DnsQueryName}";
                summary = frame.DnsQueryName is null ? "DNS traffic was identified, but a complete query name was not available in this frame." : $"A DNS message referencing {frame.DnsQueryName} was observed. A single frame does not establish whether resolution succeeded.";
                tags.Add("name-resolution");
                if (frame.DnsQueryName is not null) evidence.Add(new("Queried name", frame.DnsQueryName, "Name decoded from the DNS question section."));
                if (TryGetPayload(frame, out var dnsBytes, out var dnsOffset, out var dnsLength))
                    DecodeDns(dnsBytes, dnsOffset, dnsLength, evidence, advice);
                advice.Add("Compare the request with its matching response and inspect the response code and answer records to assess resolution.");
                break;
            case NetworkProtocol.HTTP:
                category = "Web traffic"; headline = "HTTP request or response"; summary = "Cleartext HTTP was identified from its message start. Header and body contents are not treated as safe diagnostics.";
                tags.Add("cleartext");
                if (TryGetPayload(frame, out var httpBytes, out var httpOffset, out var httpLength)) DecodeHttp(httpBytes, httpOffset, httpLength, evidence, ref headline, advice);
                advice.Add("Treat HTTP contents as unencrypted; use HTTPS where the service supports it."); break;
            case NetworkProtocol.TLS:
                category = "Encrypted web traffic"; headline = "TLS handshake or record"; summary = "TLS framing was identified. Application data is encrypted and cannot be interpreted from this packet alone.";
                tags.Add("encrypted");
                if (TryGetPayload(frame, out var tlsBytes, out var tlsOffset, out var tlsLength)) DecodeTlsClientHello(tlsBytes, tlsOffset, tlsLength, evidence, ref headline);
                advice.Add("Use the handshake and flow context to inspect negotiated TLS details; encrypted application data remains opaque here."); break;
            case NetworkProtocol.TCP when frame.TcpFlags is { } flags && (flags & 0x04) != 0:
                category = "Connection lifecycle"; headline = "TCP reset observed"; summary = "This TCP segment carries RST. It indicates an abrupt reset, but does not by itself identify which endpoint or condition caused it.";
                tags.Add("tcp-reset"); advice.Add("Inspect both directions and preceding handshake/data packets before attributing the reset to an application, firewall, or remote host."); break;
            case NetworkProtocol.ICMP:
            case NetworkProtocol.ICMPv6:
                category = "Network diagnostics"; headline = $"{frame.Protocol} control message"; summary = "An ICMP control or diagnostic message was captured; interpret its type and code with the related flow.";
                tags.Add("diagnostic"); advice.Add("Correlate this message with the destination flow and timestamp to identify the affected connection."); break;
            case NetworkProtocol.ARP:
                category = "Local network discovery"; headline = "Address resolution (ARP)"; summary = "An ARP frame was captured on the local link.";
                tags.Add("local-link"); advice.Add("Compare sender and target addresses with neighboring ARP frames if investigating duplicate or missing address resolution."); break;
        }

        if (frame.IpTtl is { } ttl) evidence.Add(new("TTL / hop limit", ttl.ToString(), "Remaining network hop limit in the IP header."));
        if (frame.TcpFlags is { } tcpFlags) evidence.Add(new("TCP flags", string.Join(", ", new[] { (0x02,"SYN"),(0x10,"ACK"),(0x01,"FIN"),(0x04,"RST"),(0x08,"PSH"),(0x20,"URG") }.Where(x => (tcpFlags & x.Item1) != 0).Select(x => x.Item2)), "Control bits set on this TCP segment."));
        return new PacketInterpretation { Category = category, Headline = headline, Summary = summary, Tags = tags, Evidence = evidence, Recommendations = advice, RuleMatchStrength = frame.Protocol is NetworkProtocol.DNS or NetworkProtocol.HTTP or NetworkProtocol.TLS ? 90 : 75, MatchBasis = "Deterministic protocol and header-field match; this describes the observed frame, not intent or threat probability." };
    }

    private static bool TryGetPayload(PacketFrame frame, out byte[] bytes, out int offset, out int length)
    {
        bytes = frame.RawData ?? Array.Empty<byte>(); offset = frame.TransportPayloadOffset ?? -1; length = 0;
        if (offset < 0 || offset >= bytes.Length) return false;
        length = Math.Min(bytes.Length - offset, 16 * 1024);
        // DNS over TCP starts with its two-byte message length prefix.
        if (frame.Protocol == NetworkProtocol.DNS && frame.TransportProtocol == NetworkProtocol.TCP)
        {
            if (length < 2) return false;
            var dnsLength = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, 2));
            offset += 2; length = Math.Min(length - 2, dnsLength);
        }
        return length > 0;
    }

    private static void DecodeDns(byte[] data, int offset, int length, List<EvidenceObservation> evidence, List<string> advice)
    {
        if (length < 12 || offset < 0 || offset + length > data.Length) return;
        var packet = data.AsSpan(offset, length);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(4, 2));
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
        var response = (flags & 0x8000) != 0;
        var rcode = flags & 0x000F;
        var rcodeName = rcode switch { 0 => "No error", 1 => "Format error", 2 => "Server failure", 3 => "Name does not exist (NXDOMAIN)", 4 => "Not implemented", 5 => "Refused", _ => $"DNS response code {rcode}" };
        evidence.Add(new("DNS message", response ? "Response" : "Query", "Direction is determined by the DNS response flag."));
        evidence.Add(new("DNS questions / answers", $"{questionCount} / {answerCount}", "Counts reported in the DNS header."));
        if (response) evidence.Add(new("DNS response code", rcodeName, "Result code in the DNS response header."));
        if (questionCount > 0 && TrySkipDnsName(packet, 12, out var questionEnd) && questionEnd + 4 <= packet.Length)
        {
            var qtype = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(questionEnd, 2));
            var qclass = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(questionEnd + 2, 2));
            evidence.Add(new("DNS query type / class", $"{TypeName(qtype)} / {(qclass == 1 ? "IN" : qclass.ToString())}", "Question record type and class."));
        }
        if (response && rcode != 0) advice.Insert(0, $"The DNS response reports {rcodeName}; compare the responding resolver and matching query before changing DNS settings.");
        if (response && answerCount > 0 && questionCount > 0 && TrySkipDnsName(packet, 12, out var qEnd) && qEnd + 4 <= packet.Length)
        {
            var cursor = qEnd + 4;
            for (var i = 0; i < Math.Min((int)answerCount, 16) && cursor + 12 <= packet.Length; i++)
            {
                if (!TrySkipDnsName(packet, cursor, out var nameEnd) || nameEnd + 10 > packet.Length) break;
                var type = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(nameEnd, 2));
                var rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(nameEnd + 8, 2));
                var rdata = nameEnd + 10;
                if (rdata + rdLength > packet.Length) break;
                string? value = type switch
                {
                    1 when rdLength == 4 => new System.Net.IPAddress(packet.Slice(rdata, 4)).ToString(),
                    28 when rdLength == 16 => new System.Net.IPAddress(packet.Slice(rdata, 16)).ToString(),
                    5 when TryReadDnsName(packet, rdata, out var cname) => cname,
                    _ => null
                };
                if (value is not null) evidence.Add(new("DNS answer", $"{TypeName(type)} {value}", "Resource record decoded from the answer section."));
                cursor = rdata + rdLength;
            }
        }
    }

    private static string TypeName(ushort type) => type switch { 1 => "A", 28 => "AAAA", 5 => "CNAME", 15 => "MX", 16 => "TXT", 2 => "NS", _ => $"TYPE{type}" };

    private static bool TrySkipDnsName(ReadOnlySpan<byte> packet, int start, out int end)
    {
        end = start; var cursor = start; var jumps = 0; var wireLength = 0; var jumped = false;
        while (cursor < packet.Length && jumps <= 16 && wireLength <= 255)
        {
            var size = packet[cursor];
            if (size == 0) { end = jumped ? end : cursor + 1; return true; }
            if ((size & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= packet.Length) return false;
                var pointer = ((size & 0x3F) << 8) | packet[cursor + 1];
                if (pointer >= packet.Length) return false;
                if (!jumped) { end = cursor + 2; jumped = true; }
                cursor = pointer; jumps++; continue;
            }
            if ((size & 0xC0) != 0 || size > 63 || cursor + 1 + size > packet.Length) return false;
            cursor += 1 + size; wireLength += size + 1;
        }
        return false;
    }

    private static bool TryReadDnsName(ReadOnlySpan<byte> packet, int start, out string name)
    {
        name = string.Empty;
        if (start < 0 || start >= packet.Length) return false;
        if (!TrySkipDnsName(packet, start, out var end)) return false;
        var labels = new List<string>(); var cursor = start; var jumps = 0; var wireLength = 0;
        while (cursor < packet.Length && jumps++ <= 16)
        {
            var size = packet[cursor++];
            if (size == 0) break;
            if ((size & 0xC0) == 0xC0) { if (cursor >= packet.Length) return false; cursor = ((size & 0x3F) << 8) | packet[cursor]; continue; }
            if (size > 63 || cursor + size > packet.Length) return false;
            if (!IsPlausibleDnsLabel(packet.Slice(cursor, size))) return false;
            wireLength += size + 1;
            if (wireLength > 255) return false;
            labels.Add(Encoding.ASCII.GetString(packet.Slice(cursor, size))); cursor += size;
        }
        name = string.Join('.', labels); return end > start && labels.Count > 0;
    }

    /// <summary>
    /// Rejects label bytes that are not hostname-shaped so decoded names can never smuggle control
    /// characters, quotes, or line breaks into evidence lists and reports.
    /// </summary>
    private static bool IsPlausibleDnsLabel(ReadOnlySpan<byte> label)
    {
        if (label.Length == 0) return false;
        foreach (var value in label)
        {
            if (value is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_' or (byte)'.') continue;
            return false;
        }
        return true;
    }

    /// <summary>
    /// Replaces control characters in captured text with a visible placeholder and bounds its length.
    /// Captured headers are attacker-controlled bytes, so they must never reach the UI or an export verbatim.
    /// </summary>
    private static string Printable(string value, int maximumLength)
    {
        var limited = value.Length <= maximumLength ? value : value[..maximumLength];
        return string.Create(limited.Length, limited, static (destination, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var character = source[i];
                destination[i] = char.IsControl(character) ? '\u00B7' : character;
            }
        });
    }

    private static void DecodeHttp(byte[] data, int offset, int length, List<EvidenceObservation> evidence, ref string headline, List<string> advice)
    {
        var bytes = data.AsSpan(offset, Math.Min(length, 16 * 1024));
        var end = bytes.IndexOf("\r\n\r\n"u8);
        if (end < 0) end = bytes.Length;
        var text = Encoding.Latin1.GetString(bytes[..end]);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0) return;
        var first = Printable(lines[0].Trim(), 512);
        if (first.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            var parts = first.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2) { evidence.Add(new("HTTP status", parts[1] + (parts.Length == 3 ? $" {parts[2]}" : ""), "Status line from a cleartext HTTP response.")); headline = $"HTTP response {parts[1]}"; }
        }
        else
        {
            var parts = first.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                var safeTarget = parts[1].Split('?', '#')[0];
                evidence.Add(new("HTTP request", $"{parts[0]} {safeTarget}", "Request line from cleartext HTTP; query strings and fragments are omitted because they can contain tokens or personal data."));
                headline = $"HTTP {parts[0]} request";
            }
        }
        foreach (var line in lines.Skip(1).Take(100))
        {
            var colon = line.IndexOf(':'); if (colon <= 0) continue;
            var name = line[..colon].Trim(); var value = line[(colon + 1)..].Trim();
            if (value.Length == 0 || name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) || name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) || name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) || name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase) || name.Equals("Server", StringComparison.OrdinalIgnoreCase) || name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase) || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                evidence.Add(new($"HTTP {Printable(name, 64)}", Printable(value, 256), "Non-credential HTTP header observed in the captured request or response; control characters are masked."));
        }
        advice.Add("Review cleartext request targets and headers with care; this view deliberately omits authorization and cookie values.");
    }

    private static void DecodeTlsClientHello(byte[] data, int offset, int length, List<EvidenceObservation> evidence, ref string headline)
    {
        var record = data.AsSpan(offset, Math.Min(length, 16 * 1024));
        if (record.Length < 9 || record[0] != 0x16 || record[5] != 0x01) return;
        var cursor = 9; // TLS record header (5) + handshake header (4)
        if (cursor + 34 > record.Length) return;
        cursor += 34; // legacy version and random
        if (cursor >= record.Length) return; cursor += 1 + record[cursor]; // session id
        if (cursor + 2 > record.Length) return;
        var cipherBytes = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(cursor, 2)); cursor += 2;
        if (cursor + cipherBytes + 1 > record.Length) return; cursor += cipherBytes;
        var compressionBytes = record[cursor++]; if (cursor + compressionBytes + 2 > record.Length) return; cursor += compressionBytes;
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(cursor, 2)); cursor += 2;
        var end = Math.Min(record.Length, cursor + extensionsLength);
        evidence.Add(new("TLS handshake", "ClientHello", "ClientHello handshake type decoded from the TLS record."));
        while (cursor + 4 <= end)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(cursor, 2)); var size = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(cursor + 2, 2)); cursor += 4;
            if (cursor + size > end) return;
            if (type == 0 && size >= 5)
            {
                var ext = record.Slice(cursor, size); var listLength = BinaryPrimitives.ReadUInt16BigEndian(ext.Slice(0, 2)); var p = 2; var listEnd = Math.Min(ext.Length, 2 + listLength);
                while (p + 3 <= listEnd)
                {
                    var nameType = ext[p++]; var nameLength = BinaryPrimitives.ReadUInt16BigEndian(ext.Slice(p, 2)); p += 2;
                    if (p + nameLength > listEnd) break;
                    if (nameType == 0 && nameLength is > 0 and <= 253)
                    {
                        var host = Encoding.ASCII.GetString(ext.Slice(p, nameLength));
                        if (host.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-'))
                        { evidence.Add(new("TLS server name", host, "SNI hostname advertised by the client; encrypted application data is not decoded.")); headline = $"TLS handshake for {host}"; }
                        break;
                    }
                    p += nameLength;
                }
            }
            cursor += size;
        }
    }
}
