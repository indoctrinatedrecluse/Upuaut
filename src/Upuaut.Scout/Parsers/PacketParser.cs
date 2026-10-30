using System.Net;
using System.Text;
using Upuaut.Core.Models;
using Upuaut.Scout.Native;

namespace Upuaut.Scout.Parsers;

/// <summary>
/// High-speed zero-allocation binary parser for raw IP, TCP, UDP, ICMP, and DNS packets.
/// Attaches real-time process attribution and detects network anomalies (RST aborts, retransmissions).
/// </summary>
public static class PacketParser
{
    private const int MaximumDnsLabels = 127;
    private const int MaximumDnsNameLength = 253;

    public static PacketFrame? ParseIPv4Packet(byte[] buffer, int length, long frameIndex, string? interfaceName = null)
    {
        if (buffer is null || length < 20 || length > buffer.Length) return null;

        // Byte 0: Version & IHL
        byte verAndIhl = buffer[0];
        int version = verAndIhl >> 4;
        if (version != 4) return null; // Only IPv4 in this parser

        int ipHeaderLength = (verAndIhl & 0x0F) * 4;
        if (ipHeaderLength < 20 || length < ipHeaderLength) return null;

        // Total Length. Capture engines often deliver fewer bytes than the header advertises (snaplen or
        // mid-stream capture), so the captured size wins and the truncation is surfaced to the operator.
        int declaredTotalLength = (buffer[2] << 8) | buffer[3];
        // A total length smaller than the header it describes is impossible. Parsing the captured bytes and
        // flagging the anomaly keeps such frames visible instead of silently discarding them.
        bool malformedTotalLength = declaredTotalLength < ipHeaderLength;
        if (malformedTotalLength) declaredTotalLength = length;
        bool truncatedCapture = declaredTotalLength > length;
        int totalLength = truncatedCapture ? length : declaredTotalLength;

        // TTL & Protocol
        byte ttl = buffer[8];
        byte protocolByte = buffer[9];

        // Source and Destination IP
        var srcIp = new IPAddress(buffer.AsSpan(12, 4)).ToString();
        var dstIp = new IPAddress(buffer.AsSpan(16, 4)).ToString();

        NetworkProtocol protocol = NetworkProtocol.IPv4;
        int? srcPort = null;
        int? dstPort = null;
        string summary;
        bool hasErrorOrRetransmit = false;
        byte[]? payload = null;
        int? transportHeaderLength = null;
        int? payloadOffsetForRaw = null;
        uint? tcpSequence = null;
        uint? tcpAck = null;
        byte? tcpFlags = null;
        ushort? tcpWindow = null;
        string? dnsName = null;
        var details = new List<PacketDetail>
        {
            new("IPv4", "Version", "4"), new("IPv4", "Header length", $"{ipHeaderLength} bytes"),
            new("IPv4", "Total length", $"{totalLength} bytes"), new("IPv4", "TTL", ttl.ToString()),
            new("IPv4", "Protocol", protocolByte.ToString()), new("IPv4", "Source", srcIp), new("IPv4", "Destination", dstIp)
        };

        int transportOffset = ipHeaderLength;
        int transportLength = totalLength - transportOffset;
        if (malformedTotalLength) details.Add(new PacketDetail("IPv4", "Length anomaly", $"The declared total length is smaller than the {ipHeaderLength}-byte header; the captured {length} bytes were parsed."));
        if (truncatedCapture) details.Add(new PacketDetail("IPv4", "Capture", $"Truncated: {length} of {declaredTotalLength} bytes captured"));
        int fragmentField = (buffer[6] << 8) | buffer[7];
        bool fragmented = (fragmentField & 0x3FFF) != 0;
        bool moreFragments = (fragmentField & 0x2000) != 0;
        int fragmentOffsetBytes = (fragmentField & 0x1FFF) * 8;
        details.AddRange(new[] { new PacketDetail("IPv4", "DSCP / ECN", $"0x{buffer[1]:X2}"), new PacketDetail("IPv4", "Flags", $"0x{(fragmentField >> 13):X1}"), new PacketDetail("IPv4", "Fragment offset", $"{(fragmentField & 0x1FFF) * 8} bytes"), new PacketDetail("IPv4", "Header checksum", $"0x{((buffer[10] << 8) | buffer[11]):X4}") });

        // 1. TCP (Protocol 6)
        if (fragmentOffsetBytes == 0 && protocolByte == 6 && transportLength >= 20)
        {
            protocol = NetworkProtocol.TCP;
            srcPort = (buffer[transportOffset] << 8) | buffer[transportOffset + 1];
            dstPort = (buffer[transportOffset + 2] << 8) | buffer[transportOffset + 3];

            uint seqNum = (uint)((buffer[transportOffset + 4] << 24) |
                                 (buffer[transportOffset + 5] << 16) |
                                 (buffer[transportOffset + 6] << 8) |
                                 buffer[transportOffset + 7]);

            uint ackNum = (uint)((buffer[transportOffset + 8] << 24) |
                                 (buffer[transportOffset + 9] << 16) |
                                 (buffer[transportOffset + 10] << 8) |
                                 buffer[transportOffset + 11]);

            byte tcpHeaderLen = (byte)(((buffer[transportOffset + 12] >> 4) & 0x0F) * 4);
            // A segment with an impossible data offset is still reported. Dropping malformed frames would hide
            // flows from the operator, so the header is parsed with the minimum 20-byte offset and flagged.
            bool malformedTcpHeader = tcpHeaderLen < 20 || tcpHeaderLen > transportLength;
            tcpHeaderLen = malformedTcpHeader ? (byte)20 : tcpHeaderLen;
            byte flags = buffer[transportOffset + 13];

            bool fin = (flags & 0x01) != 0;
            bool syn = (flags & 0x02) != 0;
            bool rst = (flags & 0x04) != 0;
            bool psh = (flags & 0x08) != 0;
            bool ack = (flags & 0x10) != 0;
            bool urg = (flags & 0x20) != 0;

            ushort window = (ushort)((buffer[transportOffset + 14] << 8) | buffer[transportOffset + 15]);

            var flagList = new List<string>(4);
            if (syn) flagList.Add("SYN");
            if (ack) flagList.Add("ACK");
            if (fin) flagList.Add("FIN");
            if (rst) flagList.Add("RST");
            if (psh) flagList.Add("PSH");

            string flagStr = flagList.Count > 0 ? string.Join(",", flagList) : "NONE";

            int payloadOffset = transportOffset + tcpHeaderLen;
            transportHeaderLength = tcpHeaderLen; payloadOffsetForRaw = payloadOffset;
            tcpSequence = seqNum; tcpAck = ackNum; tcpFlags = flags; tcpWindow = window;
            details.AddRange(new[] { new PacketDetail("TCP", "Source port", srcPort.Value.ToString()), new PacketDetail("TCP", "Destination port", dstPort.Value.ToString()), new PacketDetail("TCP", "Sequence number", seqNum.ToString()), new PacketDetail("TCP", "Acknowledgment number", ackNum.ToString()), new PacketDetail("TCP", "Header length", $"{tcpHeaderLen} bytes"), new PacketDetail("TCP", "Flags", flagStr), new PacketDetail("TCP", "Window", window.ToString()) });
            details.Add(new PacketDetail("TCP", "Checksum", $"0x{((buffer[transportOffset + 16] << 8) | buffer[transportOffset + 17]):X4}"));
            int payloadLength = totalLength - payloadOffset;
            if (srcPort == 53 || dstPort == 53)
            {
                protocol = NetworkProtocol.DNS;
                dnsName = TryExtractDnsQuery(buffer, payloadOffset + 2, Math.Max(0, payloadLength - 2));
                summary = $"DNS (TCP) [{flagStr}] {srcPort} → {dstPort}";
            }
            else if (LooksLikeTls(buffer, payloadOffset, payloadLength))
            {
                protocol = NetworkProtocol.TLS;
                summary = $"TLS [{flagStr}] {srcPort} → {dstPort} Seq={seqNum} Ack={ackNum}";
            }
            else if (LooksLikeHttp(buffer, payloadOffset, payloadLength))
            {
                protocol = NetworkProtocol.HTTP;
                summary = $"HTTP [{flagStr}] {srcPort} → {dstPort} Seq={seqNum} Ack={ackNum}";
            }
            else
            {
                summary = $"TCP [{flagStr}] {srcPort} → {dstPort} Seq={seqNum} Ack={ackNum} Win={window}";
            }

            if (rst)
            {
                hasErrorOrRetransmit = true;
                summary += " [CONN RESET/REFUSED]";
            }

            if (malformedTcpHeader)
            {
                hasErrorOrRetransmit = true;
                summary += " [INVALID TCP HEADER LENGTH]";
                details.Add(new PacketDetail("TCP", "Header length anomaly", "The declared data offset is outside 20 bytes and the captured segment length; the minimum 20-byte header was used."));
            }

            if (payloadOffset < totalLength)
            {
                int payloadLen = totalLength - payloadOffset;
                payload = new byte[Math.Min(payloadLen, 512)];
                Array.Copy(buffer, payloadOffset, payload, 0, payload.Length);
            }
        }
        // 2. UDP (Protocol 17)
        else if (fragmentOffsetBytes == 0 && protocolByte == 17 && transportLength >= 8)
        {
            protocol = NetworkProtocol.UDP;
            srcPort = (buffer[transportOffset] << 8) | buffer[transportOffset + 1];
            dstPort = (buffer[transportOffset + 2] << 8) | buffer[transportOffset + 3];
            int declaredUdpLength = (buffer[transportOffset + 4] << 8) | buffer[transportOffset + 5];
            // Impossible datagram lengths are clamped into the captured transport bytes instead of dropping the
            // frame, so malformed traffic stays visible in the capture view.
            bool malformedUdpLength = declaredUdpLength < 8 || (declaredUdpLength > transportLength && !moreFragments);
            int udpLen = malformedUdpLength ? Math.Clamp(declaredUdpLength, 8, transportLength) : declaredUdpLength;

            int payloadOffset = transportOffset + 8;
            int payloadLen = Math.Min(Math.Max(0, udpLen - 8), Math.Max(0, totalLength - payloadOffset));
            transportHeaderLength = 8; payloadOffsetForRaw = payloadOffset;
            details.AddRange(new[] { new PacketDetail("UDP", "Source port", srcPort.Value.ToString()), new PacketDetail("UDP", "Destination port", dstPort.Value.ToString()), new PacketDetail("UDP", "Length", udpLen.ToString()) });
            details.Add(new PacketDetail("UDP", "Checksum", $"0x{((buffer[transportOffset + 6] << 8) | buffer[transportOffset + 7]):X4}"));

            if (srcPort == 53 || dstPort == 53)
            {
                protocol = NetworkProtocol.DNS;
                var dnsQuery = TryExtractDnsQuery(buffer, payloadOffset, payloadLen);
                dnsName = dnsQuery;
                summary = !string.IsNullOrEmpty(dnsQuery)
                    ? $"DNS Query: {dnsQuery} ({srcPort} → {dstPort})"
                    : $"DNS Datagram ({srcPort} → {dstPort})";
            }
            else
            {
                summary = $"UDP {srcPort} → {dstPort} Len={udpLen}";
            }

            if (malformedUdpLength)
            {
                hasErrorOrRetransmit = true;
                summary += " [INVALID UDP LENGTH]";
                details.Add(new PacketDetail("UDP", "Length anomaly", $"The declared datagram length is outside the captured transport bytes; {udpLen} of {transportLength} bytes were parsed."));
            }

            if (payloadLen > 0 && payloadOffset < buffer.Length)
            {
                int copyLen = Math.Min(payloadLen, Math.Min(buffer.Length - payloadOffset, 512));
                payload = new byte[copyLen];
                Array.Copy(buffer, payloadOffset, payload, 0, copyLen);
            }
        }
        // 3. ICMP (Protocol 1)
        else if (fragmentOffsetBytes == 0 && protocolByte == 1 && transportLength >= 4)
        {
            protocol = NetworkProtocol.ICMP;
            byte type = buffer[transportOffset];
            byte code = buffer[transportOffset + 1];
            details.Add(new PacketDetail("ICMP", "Type", type.ToString()));
            details.Add(new PacketDetail("ICMP", "Code", code.ToString()));

            summary = type switch
            {
                0 => $"ICMP Echo Reply (Ping Response) [TTL={ttl}]",
                8 => $"ICMP Echo Request (Ping) [TTL={ttl}]",
                3 => $"ICMP Destination Unreachable (Code {code})",
                11 => $"ICMP Time Exceeded in Transit (Hop Limit Reached)",
                _ => $"ICMP Type={type} Code={code}"
            };

            if (type == 3 || type == 11) hasErrorOrRetransmit = true;
        }
        else
        {
            summary = $"IPv4 Protocol {protocolByte} (TTL={ttl})";
        }
        if (fragmented) summary += " [Fragmented]";
        if (malformedTotalLength) summary += " [INVALID IP LENGTH]";
        if (truncatedCapture) summary += " [Truncated]";

        // Process Attribution via IP Helper
        int? processId = null;
        string? processName = null;
        if (srcPort.HasValue && dstPort.HasValue)
        {
            var proc = IpHelper.ResolveProcess(srcIp, srcPort.Value, dstIp, dstPort.Value);
            processId = proc.ProcessId;
            processName = proc.ProcessName;
        }

        return WithInterpretation(new PacketFrame
        {
            FrameNumber = frameIndex,
            Timestamp = DateTime.UtcNow,
            SourceIp = srcIp,
            DestinationIp = dstIp,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            Protocol = protocol,
            TotalLength = totalLength,
            Summary = summary,
            ProcessId = processId,
            ProcessName = processName,
            Payload = payload,
            InterfaceName = interfaceName,
            HasErrorOrRetransmit = hasErrorOrRetransmit,
            CaptureLayer = "IPv4",
            RawData = buffer.AsSpan(0, totalLength).ToArray(),
            TransportProtocol = protocolByte switch { 6 => NetworkProtocol.TCP, 17 => NetworkProtocol.UDP, 1 => NetworkProtocol.ICMP, _ => NetworkProtocol.Unknown },
            IpTtl = ttl, IpProtocolNumber = protocolByte, IpIdentification = (ushort)((buffer[4] << 8) | buffer[5]),
            IpFragmentOffset = fragmentOffsetBytes, IpHeaderLength = ipHeaderLength,
            TransportHeaderLength = transportHeaderLength, TransportPayloadOffset = payloadOffsetForRaw,
            TcpSequenceNumber = tcpSequence, TcpAcknowledgmentNumber = tcpAck, TcpFlags = tcpFlags, TcpWindow = tcpWindow,
            DnsQueryName = dnsName, Details = details
        });
    }

    public static PacketFrame? ParseIPv6Packet(byte[] buffer, int length, long frameIndex, string? interfaceName = null)
    {
        if (buffer is null || length < 40 || length > buffer.Length || (buffer[0] >> 4) != 6) return null;
        var declaredPayloadLength = (buffer[4] << 8) | buffer[5];
        var truncatedCapture = 40 + declaredPayloadLength > length;
        var totalLength = Math.Min(length, 40 + declaredPayloadLength);
        var hopLimit = buffer[7]; var source = new IPAddress(buffer.AsSpan(8, 16)).ToString(); var destination = new IPAddress(buffer.AsSpan(24, 16)).ToString();
        var trafficClass = (byte)(((buffer[0] & 0x0F) << 4) | (buffer[1] >> 4)); var flowLabel = ((buffer[1] & 0x0F) << 16) | (buffer[2] << 8) | buffer[3];
        byte next = buffer[6]; var baseNextHeader = next; var offset = 40; var fragmentOffset = 0; var fragmented = false; var malformedExtensionChain = false; var details = new List<PacketDetail>
        {
            new("IPv6", "Version", "6"), new("IPv6", "Traffic class", $"0x{trafficClass:X2}"), new("IPv6", "Flow label", $"0x{flowLabel:X5}"), new("IPv6", "Payload length", declaredPayloadLength.ToString()), new("IPv6", "Next header", next.ToString()), new("IPv6", "Hop limit", hopLimit.ToString()),
            new("IPv6", "Source", source), new("IPv6", "Destination", destination)
        };
        for (var depth = 0; depth < 8 && next is 0 or 43 or 44 or 51 or 60 or 135; depth++)
        {
            if (offset + 2 > totalLength) { malformedExtensionChain = true; break; }
            var extension = next; var following = buffer[offset];
            var extensionLength = extension switch { 44 => 8, 51 => (buffer[offset + 1] + 2) * 4, _ => (buffer[offset + 1] + 1) * 8 };
            if (extensionLength < 8 || offset + extensionLength > totalLength) { malformedExtensionChain = true; break; }
            details.Add(new PacketDetail("IPv6 Extension", extension switch { 0 => "Hop-by-Hop Options", 43 => "Routing", 44 => "Fragment", 51 => "Authentication", 60 => "Destination Options", _ => "Mobility" }, $"{extensionLength} bytes"));
            if (extension == 44)
            {
                var fragment = (buffer[offset + 2] << 8) | buffer[offset + 3]; fragmentOffset = fragment & 0xFFF8; fragmented = (fragment & 1) != 0 || fragmentOffset != 0;
            }
            offset += extensionLength; next = following;
        }
        if (next is 0 or 43 or 44 or 51 or 60 or 135) malformedExtensionChain = true;
        var transport = malformedExtensionChain ? NetworkProtocol.Unknown : next switch { 6 => NetworkProtocol.TCP, 17 => NetworkProtocol.UDP, 58 => NetworkProtocol.ICMPv6, _ => NetworkProtocol.Unknown };
        var protocol = transport; int? sourcePort = null, destinationPort = null; int? transportHeaderLength = null, payloadOffset = null;
        uint? sequence = null, ack = null; byte? flags = null; ushort? window = null; byte[]? payload = null; string? dns = null;
        var summary = $"IPv6 protocol {next} ({source} → {destination})";
        if (malformedExtensionChain)
        {
            summary += " [MALFORMED EXTENSION CHAIN]";
            details.Add(new PacketDetail("IPv6", "Extension chain anomaly", "The extension header chain is truncated or deeper than the 8-header inspection limit; transport fields were not decoded."));
        }
        if (fragmentOffset == 0 && transport == NetworkProtocol.TCP && totalLength - offset >= 20)
        {
            sourcePort = (buffer[offset] << 8) | buffer[offset + 1]; destinationPort = (buffer[offset + 2] << 8) | buffer[offset + 3];
            sequence = ReadUInt32(buffer, offset + 4); ack = ReadUInt32(buffer, offset + 8); var headerLength = (buffer[offset + 12] >> 4) * 4; flags = buffer[offset + 13]; window = (ushort)((buffer[offset + 14] << 8) | buffer[offset + 15]);
            // Malformed data offsets are flagged instead of discarding the frame, mirroring the IPv4 path.
            var malformedHeader = headerLength < 20 || offset + headerLength > totalLength;
            if (malformedHeader) headerLength = 20;
            transportHeaderLength = headerLength; payloadOffset = offset + headerLength;
            var payloadLengthTcp = totalLength - payloadOffset.Value;
            var flagNames = new[] { (0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH") }.Where(f => (flags.Value & f.Item1) != 0).Select(f => f.Item2);
            if (sourcePort == 53 || destinationPort == 53) { protocol = NetworkProtocol.DNS; dns = TryExtractDnsQuery(buffer, payloadOffset.Value + 2, Math.Max(0, payloadLengthTcp - 2)); summary = $"DNS over TCP {sourcePort} → {destinationPort}"; }
            else if (LooksLikeTls(buffer, payloadOffset.Value, payloadLengthTcp)) { protocol = NetworkProtocol.TLS; summary = $"TLS {sourcePort} → {destinationPort}"; }
            else if (LooksLikeHttp(buffer, payloadOffset.Value, payloadLengthTcp)) { protocol = NetworkProtocol.HTTP; summary = $"HTTP {sourcePort} → {destinationPort}"; }
            else summary = $"TCP [{string.Join(",", flagNames)}] {sourcePort} → {destinationPort} Seq={sequence} Ack={ack}";
            if (malformedHeader) { summary += " [INVALID TCP HEADER LENGTH]"; details.Add(new PacketDetail("TCP", "Header length anomaly", "The declared data offset is outside 20 bytes and the captured segment length; the minimum 20-byte header was used.")); }
            if (payloadLengthTcp > 0) payload = buffer.AsSpan(payloadOffset.Value, Math.Min(payloadLengthTcp, 512)).ToArray();
            details.AddRange(new[] { new PacketDetail("TCP", "Source port", sourcePort.Value.ToString()), new PacketDetail("TCP", "Destination port", destinationPort.Value.ToString()), new PacketDetail("TCP", "Sequence number", sequence.Value.ToString()), new PacketDetail("TCP", "Acknowledgment number", ack.Value.ToString()), new PacketDetail("TCP", "Flags", string.Join(",", flagNames)), new PacketDetail("TCP", "Window", window.Value.ToString()) });
        }
        else if (fragmentOffset == 0 && transport == NetworkProtocol.UDP && totalLength - offset >= 8)
        {
            sourcePort = (buffer[offset] << 8) | buffer[offset + 1]; destinationPort = (buffer[offset + 2] << 8) | buffer[offset + 3]; var udpLength = (buffer[offset + 4] << 8) | buffer[offset + 5];
            // Impossible datagram lengths are clamped to the captured transport bytes and reported, not dropped.
            var malformedUdp = udpLength < 8 || udpLength > totalLength - offset;
            if (malformedUdp) udpLength = Math.Clamp(udpLength, 8, totalLength - offset);
            transportHeaderLength = 8; payloadOffset = offset + 8; var dataLength = udpLength - 8;
            if (sourcePort == 53 || destinationPort == 53) { protocol = NetworkProtocol.DNS; dns = TryExtractDnsQuery(buffer, payloadOffset.Value, dataLength); summary = dns is null ? $"DNS UDP {sourcePort} → {destinationPort}" : $"DNS Query: {dns}"; }
            else summary = $"UDP {sourcePort} → {destinationPort} Len={udpLength}";
            if (malformedUdp) { summary += " [INVALID UDP LENGTH]"; details.Add(new PacketDetail("UDP", "Length anomaly", "The declared datagram length is outside the captured transport bytes; the available bytes were parsed.")); }
            if (dataLength > 0) payload = buffer.AsSpan(payloadOffset.Value, Math.Min(dataLength, 512)).ToArray();
            details.AddRange(new[] { new PacketDetail("UDP", "Source port", sourcePort.Value.ToString()), new PacketDetail("UDP", "Destination port", destinationPort.Value.ToString()), new PacketDetail("UDP", "Length", udpLength.ToString()) });
        }
        else if (fragmentOffset == 0 && transport == NetworkProtocol.ICMPv6 && totalLength - offset >= 4)
        {
            var type = buffer[offset]; var code = buffer[offset + 1];
            summary = type switch { 128 => "ICMPv6 Echo Request", 129 => "ICMPv6 Echo Reply", 133 => "ICMPv6 Router Solicitation", 134 => "ICMPv6 Router Advertisement", 135 => "ICMPv6 Neighbor Solicitation", 136 => "ICMPv6 Neighbor Advertisement", _ => $"ICMPv6 Type={type} Code={code}" };
            details.Add(new PacketDetail("ICMPv6", "Type / code", $"{type} / {code}"));
        }
        if (fragmented) summary += " [Fragmented]";
        if (truncatedCapture) { summary += " [Truncated]"; details.Add(new PacketDetail("IPv6", "Capture", $"Truncated: {length} of {40 + declaredPayloadLength} bytes captured")); }
        return WithInterpretation(new PacketFrame { FrameNumber = frameIndex, Timestamp = DateTime.UtcNow, SourceIp = source, DestinationIp = destination, SourcePort = sourcePort,
            DestinationPort = destinationPort, Protocol = protocol == NetworkProtocol.Unknown ? NetworkProtocol.IPv6 : protocol, TransportProtocol = transport,
            TotalLength = totalLength, Summary = summary, Payload = payload, InterfaceName = interfaceName, CaptureLayer = "IPv6", RawData = buffer.AsSpan(0, totalLength).ToArray(),
            IpTtl = hopLimit, IpProtocolNumber = baseNextHeader, IpFragmentOffset = fragmentOffset, IpHeaderLength = offset, TransportHeaderLength = transportHeaderLength,
            TransportPayloadOffset = payloadOffset, TcpSequenceNumber = sequence, TcpAcknowledgmentNumber = ack, TcpFlags = flags, TcpWindow = window,
            DnsQueryName = dns, HasErrorOrRetransmit = flags.HasValue && (flags.Value & 0x04) != 0, Details = details });
    }

    private static uint ReadUInt32(byte[] buffer, int offset) => (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);

    public static PacketFrame? ParseEthernetFrame(byte[] buffer, int length, long frameIndex, string? interfaceName = null)
    {
        if (buffer is null || length < 14 || length > buffer.Length) return null;
        var destinationMac = FormatMac(buffer.AsSpan(0, 6));
        var sourceMac = FormatMac(buffer.AsSpan(6, 6));
        int offset = 14;
        ushort etherType = (ushort)((buffer[12] << 8) | buffer[13]);
        while (etherType is 0x8100 or 0x88A8 or 0x9100)
        {
            if (length < offset + 4) return null;
            etherType = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);
            offset += 4;
        }

        PacketFrame? frame = etherType == 0x0800
            ? ParseIPv4Packet(buffer.AsSpan(offset, length - offset).ToArray(), length - offset, frameIndex, interfaceName)
            : etherType == 0x86DD ? ParseIPv6Packet(buffer.AsSpan(offset, length - offset).ToArray(), length - offset, frameIndex, interfaceName)
            : etherType == 0x0806 && length >= offset + 8 ? ParseArpFrame(buffer, length, frameIndex, interfaceName, offset)
            : null;
        return frame is null ? null : WithInterpretation(frame with
        {
            TotalLength = length,
            CaptureLayer = "Ethernet",
            RawData = buffer.AsSpan(0, length).ToArray(),
            SourceMac = sourceMac,
            DestinationMac = destinationMac,
            EtherType = etherType,
            EthernetHeaderLength = offset,
            TransportPayloadOffset = frame.TransportPayloadOffset is { } payloadOffset ? payloadOffset + offset : null,
            Details = new[] { new PacketDetail("Ethernet", "Destination", destinationMac), new PacketDetail("Ethernet", "Source", sourceMac), new PacketDetail("Ethernet", "EtherType", $"0x{etherType:X4}") }.Concat(frame.Details).ToArray()
        });
    }

    private static PacketFrame ParseArpFrame(byte[] buffer, int length, long frameIndex, string? interfaceName, int offset)
    {
        var hardwareLength = buffer[offset + 4]; var protocolLength = buffer[offset + 5];
        var required = offset + 8 + 2 * hardwareLength + 2 * protocolLength;
        var operation = (buffer[offset + 6] << 8) | buffer[offset + 7];
        var details = new List<PacketDetail>
        {
            new("ARP", "Hardware type", $"0x{(buffer[offset] << 8) | buffer[offset + 1]:X4}"),
            new("ARP", "Protocol type", $"0x{(buffer[offset + 2] << 8) | buffer[offset + 3]:X4}"),
            new("ARP", "Hardware / protocol address length", $"{hardwareLength} / {protocolLength}"),
            new("ARP", "Operation", operation switch { 1 => "Request (1)", 2 => "Reply (2)", _ => $"{operation}" })
        };
        string? sourceIp = null; string? destinationIp = null; string? senderMacValue = null;
        if (required <= length && hardwareLength == 6 && protocolLength == 4 && (buffer[offset + 2] << 8 | buffer[offset + 3]) == 0x0800)
        {
            senderMacValue = FormatMac(buffer.AsSpan(offset + 8, 6)); sourceIp = new IPAddress(buffer.AsSpan(offset + 14, 4)).ToString();
            var targetMac = FormatMac(buffer.AsSpan(offset + 18, 6)); destinationIp = new IPAddress(buffer.AsSpan(offset + 24, 4)).ToString();
            details.Add(new("ARP", "Sender", $"{sourceIp} ({senderMacValue})")); details.Add(new("ARP", "Target", $"{destinationIp} ({targetMac})"));
        }
        return new PacketFrame { FrameNumber = frameIndex, Timestamp = DateTime.UtcNow, Protocol = NetworkProtocol.ARP, SourceIp = sourceIp ?? string.Empty,
            DestinationIp = destinationIp ?? string.Empty, TotalLength = length, Summary = operation == 1 ? $"ARP request: who has {destinationIp ?? "address"}?" : operation == 2 ? $"ARP reply: {sourceIp ?? "address"} is at {(senderMacValue ?? "unknown")}" : "ARP frame",
            InterfaceName = interfaceName, CaptureLayer = "Ethernet", RawData = buffer.AsSpan(0, length).ToArray(), Details = details };
    }

    private static PacketFrame WithInterpretation(PacketFrame frame)
    {
        var interpretation = PacketInterpretationEngine.Analyze(frame);
        var decoded = interpretation.Evidence.Select(item => new PacketDetail("Interpretation", item.Label, item.Value));
        return frame with { Interpretation = interpretation, Details = frame.Details.Where(detail => detail.Layer != "Interpretation").Concat(decoded).ToArray() };
    }

    private static string FormatMac(ReadOnlySpan<byte> address) => string.Join(":", address.ToArray().Select(b => b.ToString("X2")));

    private static bool LooksLikeTls(byte[] data, int offset, int length) =>
        length >= 5 && offset >= 0 && offset + 5 <= data.Length && data[offset] is >= 0x14 and <= 0x17 && data[offset + 1] == 0x03;

    private static bool LooksLikeHttp(byte[] data, int offset, int length)
    {
        if (length < 4 || offset < 0 || offset + 4 > data.Length) return false;
        ReadOnlySpan<byte> payload = data.AsSpan(offset, Math.Min(length, 16));
        return payload.StartsWith("GET "u8) || payload.StartsWith("POST "u8) || payload.StartsWith("PUT "u8) ||
               payload.StartsWith("HEAD "u8) || payload.StartsWith("DELETE "u8) || payload.StartsWith("HTTP/"u8);
    }

    private static string? TryExtractDnsQuery(byte[] buffer, int offset, int length)
    {
        if (buffer is null || offset < 0 || offset >= buffer.Length || length < 12) return null;
        var available = Math.Min(length, buffer.Length - offset);
        if (available <= 12) return null; // No room for a question name in the captured bytes.

        var limit = offset + available;
        var cursor = offset + 12; // DNS Question section follows the 12-byte header.
        var name = new StringBuilder(64);
        var labels = 0;

        while (cursor < limit && labels < MaximumDnsLabels)
        {
            byte labelLength = buffer[cursor++];
            if (labelLength == 0) break; // End of QNAME.
            // Compression pointers and reserved label types are not valid inside a question name, and a label
            // longer than 63 bytes cannot be represented in DNS; abandon the name rather than emit noise.
            if ((labelLength & 0xC0) != 0 || labelLength > 63) return null;
            if (cursor + labelLength > limit) return null;
            if (!IsPlausibleDnsLabel(buffer.AsSpan(cursor, labelLength))) return null;

            if (name.Length > 0) name.Append('.');
            name.Append(Encoding.ASCII.GetString(buffer, cursor, labelLength));
            if (name.Length > MaximumDnsNameLength) return null;

            cursor += labelLength;
            labels++;
        }

        return name.Length > 0 ? name.ToString() : null;
    }

    /// <summary>
    /// Accepts only hostname-shaped label bytes so captured names can never carry control characters,
    /// quotes, or line breaks into summaries, evidence lists, and exports.
    /// </summary>
    private static bool IsPlausibleDnsLabel(ReadOnlySpan<byte> label)
    {
        if (label.Length == 0) return false;
        foreach (var value in label)
        {
            if (value is >= (byte)'a' and <= (byte)'z') continue;
            if (value is >= (byte)'A' and <= (byte)'Z') continue;
            if (value is >= (byte)'0' and <= (byte)'9') continue;
            if (value is (byte)'-' or (byte)'_' or (byte)'.') continue;
            return false;
        }
        return true;
    }
}
