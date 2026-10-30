using System.Net;
using System.Text;
using Upuaut.Core.Models;
using Upuaut.Scout.Parsers;
using Xunit;

namespace Upuaut.Tests;

public class ScoutPacketTests
{
    [Fact]
    public void ParsesIPv4_TCP_SynPacket()
    {
        // Construct a synthetic 40-byte IPv4 + TCP packet
        byte[] packet = new byte[40];

        // IPv4 Header (20 bytes)
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[1] = 0x00;
        packet[2] = 0x00; packet[3] = 40; // Total length: 40 bytes
        packet[8] = 64;   // TTL: 64
        packet[9] = 6;    // Protocol: TCP (6)

        // Source IP: 192.168.1.10
        packet[12] = 192; packet[13] = 168; packet[14] = 1; packet[15] = 10;
        // Dest IP: 142.250.190.46 (Google)
        packet[16] = 142; packet[17] = 250; packet[18] = 190; packet[19] = 46;

        // TCP Header (20 bytes, starts at byte 20)
        // Source Port: 52140 (0xCBAC)
        packet[20] = 0xCB; packet[21] = 0xAC;
        // Dest Port: 443 (0x01BB - HTTPS/TLS)
        packet[22] = 0x01; packet[23] = 0xBB;
        // Data offset: 5 (20 bytes)
        packet[32] = 0x50;
        // Flags: SYN (0x02)
        packet[33] = 0x02;

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 1, "Ethernet");

        Assert.NotNull(frame);
        Assert.Equal("192.168.1.10", frame.SourceIp);
        Assert.Equal("142.250.190.46", frame.DestinationIp);
        Assert.Equal(52140, frame.SourcePort);
        Assert.Equal(443, frame.DestinationPort);
        Assert.Equal(NetworkProtocol.TCP, frame.Protocol);
        Assert.Contains("SYN", frame.Summary);
    }

    [Fact]
    public void ParsesIPv4_UDP_DnsQuery()
    {
        // Construct IPv4 (20 bytes) + UDP (8 bytes) + DNS payload (24 bytes) = 52 bytes
        byte[] packet = new byte[52];

        // IPv4 Header
        packet[0] = 0x45;
        packet[2] = 0x00; packet[3] = 52; // Total length: 52
        packet[8] = 128; // TTL
        packet[9] = 17;  // Protocol: UDP (17)

        packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 1;
        packet[16] = 1; packet[17] = 1; packet[18] = 1; packet[19] = 1;

        // UDP Header (starts at byte 20)
        packet[20] = 0xC0; packet[21] = 0x00; // Source port 49152
        packet[22] = 0x00; packet[23] = 0x35; // Dest port 53 (DNS)
        packet[24] = 0x00; packet[25] = 32;   // UDP length: 32 bytes (8 header + 24 DNS payload)

        // DNS header (12 bytes, starts at byte 28)
        // Question starts at byte 40: 6 'g' 'o' 'o' 'g' 'l' 'e' 3 'c' 'o' 'm' 0
        byte[] dnsQuery = new byte[]
        {
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DNS header
            6, (byte)'g', (byte)'o', (byte)'o', (byte)'g', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m', 0
        };
        Array.Copy(dnsQuery, 0, packet, 28, dnsQuery.Length);

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 2, "Wi-Fi");

        Assert.NotNull(frame);
        Assert.Equal(53, frame.DestinationPort);
        Assert.Equal(NetworkProtocol.DNS, frame.Protocol);
        Assert.Contains("google.com", frame.Summary);
    }

    [Fact]
    public void ParsesIPv4_ICMP_EchoRequest()
    {
        byte[] packet = new byte[28];

        packet[0] = 0x45;
        packet[2] = 0x00; packet[3] = 28;
        packet[8] = 128;
        packet[9] = 1; // Protocol: ICMP (1)

        packet[12] = 192; packet[13] = 168; packet[14] = 1; packet[15] = 50;
        packet[16] = 8; packet[17] = 8; packet[18] = 8; packet[19] = 8;

        // ICMP Header (starts at byte 20)
        packet[20] = 8; // Type: 8 (Echo Request / Ping)
        packet[21] = 0; // Code: 0

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 3);

        Assert.NotNull(frame);
        Assert.Equal(NetworkProtocol.ICMP, frame.Protocol);
        Assert.Contains("Echo Request", frame.Summary);
    }

    [Fact]
    public void DetectsTcpResetFlag_AsConnectionError()
    {
        byte[] packet = new byte[40];

        packet[0] = 0x45;
        packet[2] = 0x00; packet[3] = 40;
        packet[8] = 64;
        packet[9] = 6; // TCP

        packet[12] = 192; packet[13] = 168; packet[14] = 1; packet[15] = 1;
        packet[16] = 192; packet[17] = 168; packet[18] = 1; packet[19] = 100;

        packet[20] = 0x00; packet[21] = 80; // Port 80 (HTTP)
        packet[22] = 0xD0; packet[23] = 0x00;
        packet[32] = 0x50;
        packet[33] = 0x04; // RST flag (0x04)

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 4);

        Assert.NotNull(frame);
        Assert.True(frame.HasErrorOrRetransmit);
        Assert.Contains("CONN RESET/REFUSED", frame.Summary);
    }

    [Fact]
    public void DnsQueryWithNonHostnameLabelBytesIsSuppressed()
    {
        // A crafted label carrying CR/LF and header-like text must never reach the summary or the evidence list.
        var label = Encoding.ASCII.GetBytes("evil\r\nInjected");
        var dnsLength = 12 + 1 + label.Length + 1;
        var packet = BuildUdpPacket(49152, 53, dnsLength);
        var dns = new byte[dnsLength];
        dns[5] = 1; // QDCOUNT = 1
        dns[12] = (byte)label.Length;
        label.CopyTo(dns, 13);
        dns[13 + label.Length] = 0;
        dns.CopyTo(packet, 28);

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 5);

        Assert.NotNull(frame);
        Assert.Equal(NetworkProtocol.DNS, frame.Protocol);
        Assert.Null(frame.DnsQueryName);
        Assert.DoesNotContain("\r", frame.Summary);
        Assert.DoesNotContain("\n", frame.Summary);
        Assert.DoesNotContain("Injected", frame.Summary);
        Assert.Contains("DNS Datagram", frame.Summary);
    }

    [Fact]
    public void DnsQueryWithOversizedOrPointerLabelIsSuppressed()
    {
        var label = Enumerable.Repeat((byte)'a', 64).ToArray();
        var dnsLength = 12 + 1 + label.Length + 1;
        var packet = BuildUdpPacket(49152, 53, dnsLength);
        packet[28 + 5] = 1; // QDCOUNT = 1
        packet[28 + 12] = 0x40; // Invalid label length (64) with compression bits set
        label.CopyTo(packet, 28 + 13);

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 6);

        Assert.NotNull(frame);
        Assert.Null(frame.DnsQueryName);
        Assert.Contains("DNS Datagram", frame.Summary);
    }

    [Fact]
    public void TruncatedIpv4CaptureIsFlaggedAndClamped()
    {
        var packet = new byte[40];

        packet[0] = 0x45;
        packet[2] = 0x05; packet[3] = 0xDC; // Declares 1500 bytes but only 40 were captured
        packet[8] = 64;
        packet[9] = 6; // TCP

        packet[12] = 192; packet[13] = 168; packet[14] = 0; packet[15] = 2;
        packet[16] = 192; packet[17] = 168; packet[18] = 0; packet[19] = 3;

        packet[20] = 0x1F; packet[21] = 0x90;
        packet[22] = 0x00; packet[23] = 0x50;
        packet[32] = 0x50;
        packet[33] = 0x02; // SYN

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 7);

        Assert.NotNull(frame);
        Assert.Equal(40, frame.TotalLength);
        Assert.Contains("[Truncated]", frame.Summary);
        Assert.Contains(frame.Details, detail => detail.Name == "Capture" && detail.Value.Contains("Truncated", StringComparison.Ordinal));
    }

    [Fact]
    public void TcpSegmentWithInvalidDataOffsetIsFlaggedInsteadOfDropped()
    {
        var packet = new byte[40];

        packet[0] = 0x45;
        packet[2] = 0x00; packet[3] = 40;
        packet[8] = 64;
        packet[9] = 6; // TCP

        packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 5;
        packet[16] = 10; packet[17] = 0; packet[18] = 0; packet[19] = 6;

        packet[20] = 0x30; packet[21] = 0x39;
        packet[22] = 0x01; packet[23] = 0xBB;
        packet[32] = 0x00; // Data offset 0 is impossible
        packet[33] = 0x10; // ACK

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 8);

        Assert.NotNull(frame);
        Assert.Equal(NetworkProtocol.TCP, frame.Protocol);
        Assert.True(frame.HasErrorOrRetransmit);
        Assert.Contains("[INVALID TCP HEADER LENGTH]", frame.Summary);
        Assert.Contains(frame.Details, detail => detail.Name == "Header length anomaly");
        Assert.Equal(40, frame.TransportPayloadOffset!.Value);
    }

    [Fact]
    public void UdpDatagramWithImpossibleLengthIsFlaggedInsteadOfDropped()
    {
        var packet = BuildUdpPacket(5000, 5001, 12);
        packet[24] = 0x00; packet[25] = 0x04; // Declares 4 bytes, below the 8-byte UDP header

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 9);

        Assert.NotNull(frame);
        Assert.Equal(NetworkProtocol.UDP, frame.Protocol);
        Assert.True(frame.HasErrorOrRetransmit);
        Assert.Contains("[INVALID UDP LENGTH]", frame.Summary);
        Assert.Contains(frame.Details, detail => detail.Name == "Length anomaly");
    }

    [Fact]
    public void HttpEvidenceMasksControlCharactersAndDropsQueryStrings()
    {
        var payload = Encoding.ASCII.GetBytes("GET /index.html?token=secret HTTP/1.1\r\nHost: example.test\u001b[31m\r\nUser-Agent: probe\r\n\r\n");
        var packet = new byte[20 + 20 + payload.Length];

        packet[0] = 0x45;
        packet[2] = (byte)(packet.Length >> 8); packet[3] = (byte)packet.Length;
        packet[8] = 64;
        packet[9] = 6; // TCP

        packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 7;
        packet[16] = 10; packet[17] = 0; packet[18] = 0; packet[19] = 8;

        packet[20] = 0xC0; packet[21] = 0x00;
        packet[22] = 0x00; packet[23] = 0x50;
        packet[32] = 0x50;
        packet[33] = 0x18; // PSH + ACK
        payload.CopyTo(packet, 40);

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 10);

        Assert.NotNull(frame);
        Assert.Equal(NetworkProtocol.HTTP, frame.Protocol);
        Assert.NotNull(frame.Interpretation);
        var request = Assert.Single(frame.Interpretation!.Evidence, item => item.Label == "HTTP request");
        Assert.Equal("GET /index.html", request.Value);
        var host = Assert.Single(frame.Interpretation.Evidence, item => item.Label == "HTTP Host");
        Assert.Contains("example.test", host.Value);
        Assert.All(frame.Interpretation.Evidence, item => Assert.DoesNotContain('\u001b', item.Value));
    }

    [Fact]
    public void Ipv4PacketDeclaringTotalLengthBelowHeaderIsFlaggedInsteadOfDropped()
    {
        var packet = new byte[32];

        packet[0] = 0x45;
        packet[2] = 0x00; packet[3] = 0x0A; // Declares 10 bytes, below the 20-byte header
        packet[8] = 64;
        packet[9] = 1; // ICMP

        packet[12] = 172; packet[13] = 16; packet[14] = 0; packet[15] = 1;
        packet[16] = 172; packet[17] = 16; packet[18] = 0; packet[19] = 2;

        var frame = PacketParser.ParseIPv4Packet(packet, packet.Length, 11);

        Assert.NotNull(frame);
        Assert.Equal(32, frame.TotalLength);
        Assert.Contains("[INVALID IP LENGTH]", frame.Summary);
        Assert.Contains(frame.Details, detail => detail.Name == "Length anomaly");
    }

    [Fact]
    public void Ipv6PacketWithTruncatedExtensionChainIsFlaggedInsteadOfDropped()
    {
        var packet = new byte[48];

        packet[0] = 0x60;
        packet[4] = 0x00; packet[5] = 0x64; // Declares 100 payload bytes but only 8 were captured
        packet[6] = 0; // Hop-by-Hop Options
        packet[7] = 64;
        packet[40] = 6; // Following header claims TCP
        packet[41] = 7; // Extension length ((7 + 1) * 8 = 64 bytes) exceeds the capture

        var frame = PacketParser.ParseIPv6Packet(packet, packet.Length, 12);

        Assert.NotNull(frame);
        Assert.Contains("[MALFORMED EXTENSION CHAIN]", frame.Summary);
        Assert.Contains("[Truncated]", frame.Summary);
        Assert.Contains(frame.Details, detail => detail.Name == "Extension chain anomaly");
    }

    private static byte[] BuildUdpPacket(int sourcePort, int destinationPort, int payloadLength)
    {
        var packet = new byte[20 + 8 + payloadLength];
        packet[0] = 0x45;
        packet[2] = (byte)(packet.Length >> 8); packet[3] = (byte)packet.Length;
        packet[8] = 64;
        packet[9] = 17; // UDP

        packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 1;
        packet[16] = 1; packet[17] = 1; packet[18] = 1; packet[19] = 1;

        packet[20] = (byte)(sourcePort >> 8); packet[21] = (byte)sourcePort;
        packet[22] = (byte)(destinationPort >> 8); packet[23] = (byte)destinationPort;
        var udpLength = 8 + payloadLength;
        packet[24] = (byte)(udpLength >> 8); packet[25] = (byte)udpLength;
        return packet;
    }
}
