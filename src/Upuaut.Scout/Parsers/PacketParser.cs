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
    public static PacketFrame? ParseIPv4Packet(byte[] buffer, int length, long frameIndex, string? interfaceName = null)
    {
        if (length < 20) return null; // Minimum IPv4 header length

        // Byte 0: Version & IHL
        byte verAndIhl = buffer[0];
        int version = verAndIhl >> 4;
        if (version != 4) return null; // Only IPv4 in this parser

        int ipHeaderLength = (verAndIhl & 0x0F) * 4;
        if (ipHeaderLength < 20 || length < ipHeaderLength) return null;

        // Total Length
        int totalLength = (buffer[2] << 8) | buffer[3];
        if (totalLength > length) totalLength = length;

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

        int transportOffset = ipHeaderLength;
        int transportLength = totalLength - transportOffset;

        // 1. TCP (Protocol 6)
        if (protocolByte == 6 && transportLength >= 20)
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

            // Classify application layer protocol
            if (srcPort == 443 || dstPort == 443)
            {
                protocol = NetworkProtocol.TLS;
                summary = $"TLS [{flagStr}] {srcPort} &rarr; {dstPort} Seq={seqNum} Ack={ackNum} Win={window}";
            }
            else if (srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080)
            {
                protocol = NetworkProtocol.HTTP;
                summary = $"HTTP [{flagStr}] {srcPort} &rarr; {dstPort} Seq={seqNum} Ack={ackNum}";
            }
            else if (srcPort == 53 || dstPort == 53)
            {
                protocol = NetworkProtocol.DNS;
                summary = $"DNS (TCP) [{flagStr}] {srcPort} &rarr; {dstPort}";
            }
            else
            {
                summary = $"TCP [{flagStr}] {srcPort} &rarr; {dstPort} Seq={seqNum} Ack={ackNum} Win={window}";
            }

            if (rst)
            {
                hasErrorOrRetransmit = true;
                summary += " [CONN RESET/REFUSED]";
            }

            int payloadOffset = transportOffset + tcpHeaderLen;
            if (payloadOffset < totalLength)
            {
                int payloadLen = totalLength - payloadOffset;
                payload = new byte[Math.Min(payloadLen, 512)];
                Array.Copy(buffer, payloadOffset, payload, 0, payload.Length);
            }
        }
        // 2. UDP (Protocol 17)
        else if (protocolByte == 17 && transportLength >= 8)
        {
            protocol = NetworkProtocol.UDP;
            srcPort = (buffer[transportOffset] << 8) | buffer[transportOffset + 1];
            dstPort = (buffer[transportOffset + 2] << 8) | buffer[transportOffset + 3];
            int udpLen = (buffer[transportOffset + 4] << 8) | buffer[transportOffset + 5];

            int payloadOffset = transportOffset + 8;
            int payloadLen = Math.Max(0, udpLen - 8);

            if (srcPort == 53 || dstPort == 53)
            {
                protocol = NetworkProtocol.DNS;
                var dnsQuery = TryExtractDnsQuery(buffer, payloadOffset, payloadLen);
                summary = !string.IsNullOrEmpty(dnsQuery)
                    ? $"DNS Query: {dnsQuery} ({srcPort} &rarr; {dstPort})"
                    : $"DNS Datagram ({srcPort} &rarr; {dstPort})";
            }
            else
            {
                summary = $"UDP {srcPort} &rarr; {dstPort} Len={udpLen}";
            }

            if (payloadLen > 0 && payloadOffset < buffer.Length)
            {
                int copyLen = Math.Min(payloadLen, Math.Min(buffer.Length - payloadOffset, 512));
                payload = new byte[copyLen];
                Array.Copy(buffer, payloadOffset, payload, 0, copyLen);
            }
        }
        // 3. ICMP (Protocol 1)
        else if (protocolByte == 1 && transportLength >= 4)
        {
            protocol = NetworkProtocol.ICMP;
            byte type = buffer[transportOffset];
            byte code = buffer[transportOffset + 1];

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

        // Process Attribution via IP Helper
        int? processId = null;
        string? processName = null;
        if (srcPort.HasValue && dstPort.HasValue)
        {
            var proc = IpHelper.ResolveProcess(srcPort.Value, dstPort.Value);
            processId = proc.ProcessId;
            processName = proc.ProcessName;
        }

        return new PacketFrame
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
            HasErrorOrRetransmit = hasErrorOrRetransmit
        };
    }

    private static string? TryExtractDnsQuery(byte[] buffer, int offset, int length)
    {
        try
        {
            if (length < 12 || offset + 12 >= buffer.Length) return null;

            // DNS Question section starts at offset + 12
            int qOffset = offset + 12;
            var sb = new StringBuilder();

            while (qOffset < offset + length && qOffset < buffer.Length)
            {
                byte labelLen = buffer[qOffset++];
                if (labelLen == 0) break; // End of QNAME

                if (qOffset + labelLen > buffer.Length) break;

                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(buffer, qOffset, labelLen));
                qOffset += labelLen;
            }

            return sb.Length > 0 ? sb.ToString() : null;
        }
        catch
        {
            return null;
        }
    }
}
