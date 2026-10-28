using System.Net;
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
        Assert.Equal(NetworkProtocol.TLS, frame.Protocol);
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
}
