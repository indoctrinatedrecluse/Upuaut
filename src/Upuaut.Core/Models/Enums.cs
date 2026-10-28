namespace Upuaut.Core.Models;

public enum LogSeverityLevel
{
    Verbose,
    Information,
    Warning,
    Error,
    Critical
}

public enum NetworkProtocol
{
    Unknown,
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    TLS,
    HTTP,
    ARP
}
