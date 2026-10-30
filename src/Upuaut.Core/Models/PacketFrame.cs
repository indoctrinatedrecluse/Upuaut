namespace Upuaut.Core.Models;

public record PacketFrame
{
    public long FrameNumber { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string SourceIp { get; init; } = string.Empty;
    public string DestinationIp { get; init; } = string.Empty;
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public NetworkProtocol Protocol { get; init; } = NetworkProtocol.Unknown;
    public int TotalLength { get; init; }
    public string Summary { get; init; } = string.Empty;
    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public byte[]? Payload { get; init; }
    public string? InterfaceName { get; init; }
    public bool HasErrorOrRetransmit { get; init; }
    public string CaptureLayer { get; init; } = "IPv4";
    public byte[]? RawData { get; init; }
    public string? SourceMac { get; init; }
    public string? DestinationMac { get; init; }
    public ushort? EtherType { get; init; }
}
