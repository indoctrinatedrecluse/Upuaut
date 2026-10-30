using Upuaut.Core.Models;

namespace Upuaut.Scout.Services;

/// <summary>A small Wireshark-style display-filter evaluator for common packet fields.</summary>
public static class PacketDisplayFilter
{
    public static Func<PacketFrame, bool> Compile(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression)) return _ => true;
        var terms = expression.Split("&&", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var predicates = terms.Select(ParseTerm).ToArray();
        return frame => predicates.All(predicate => predicate(frame));
    }

    private static Func<PacketFrame, bool> ParseTerm(string term)
    {
        var parts = term.Split(' ', 3, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 1)
        {
            var value = parts[0];
            if (Enum.TryParse<NetworkProtocol>(value, true, out var protocol))
                return protocol switch
                {
                    NetworkProtocol.IPv6 => f => f.CaptureLayer == "IPv6" || f.Details.Any(d => d.Layer == "IPv6"),
                    NetworkProtocol.IPv4 => f => f.CaptureLayer == "IPv4" || f.EtherType == 0x0800 || f.Details.Any(d => d.Layer == "IPv4"),
                    _ => f => f.Protocol == protocol || f.TransportProtocol == protocol
                };
            return f => Contains(f, value);
        }
        if (parts.Length != 3 || parts[1] is not ("==" or "=" or "!=" or "contains"))
            throw new FormatException($"Unsupported filter near '{term}'. Use fields such as ip.src == 10.0.0.1, tcp.port == 443, dns, or text contains example.");

        var field = parts[0].ToLowerInvariant();
        var op = parts[1];
        var expected = parts[2].Trim('"', '\'');
        Func<PacketFrame, string?> get = field switch
        {
            "ip.src" or "ipv6.src" or "src" => f => f.SourceIp,
            "ip.dst" or "ipv6.dst" or "dst" => f => f.DestinationIp,
            "tcp.port" => f => f.TransportProtocol == NetworkProtocol.TCP ? (f.SourcePort?.ToString() == expected ? f.SourcePort?.ToString() : f.DestinationPort?.ToString()) : null,
            "udp.port" => f => f.TransportProtocol == NetworkProtocol.UDP ? (f.SourcePort?.ToString() == expected ? f.SourcePort?.ToString() : f.DestinationPort?.ToString()) : null,
            "port" => f => f.SourcePort?.ToString() == expected ? f.SourcePort?.ToString() : f.DestinationPort?.ToString(),
            "tcp.srcport" => f => f.TransportProtocol == NetworkProtocol.TCP ? f.SourcePort?.ToString() : null,
            "tcp.dstport" => f => f.TransportProtocol == NetworkProtocol.TCP ? f.DestinationPort?.ToString() : null,
            "udp.srcport" => f => f.TransportProtocol == NetworkProtocol.UDP ? f.SourcePort?.ToString() : null,
            "udp.dstport" => f => f.TransportProtocol == NetworkProtocol.UDP ? f.DestinationPort?.ToString() : null,
            "dns.qry.name" => f => f.DnsQueryName,
            "frame.protocol" or "protocol" => f => f.Protocol.ToString(),
            "process" => f => f.ProcessName,
            "text" => f => f.Summary,
            _ => throw new FormatException($"Unknown packet field '{field}'.")
        };
        return f =>
        {
            var actual = get(f);
            var matches = actual is not null && (op == "contains"
                ? actual.Contains(expected, StringComparison.OrdinalIgnoreCase)
                : actual.Equals(expected, StringComparison.OrdinalIgnoreCase));
            return op == "!=" ? !matches : matches;
        };
    }

    private static bool Contains(PacketFrame f, string value) =>
        f.SourceIp.Contains(value, StringComparison.OrdinalIgnoreCase) ||
        f.DestinationIp.Contains(value, StringComparison.OrdinalIgnoreCase) ||
        f.Summary.Contains(value, StringComparison.OrdinalIgnoreCase) ||
        (f.ProcessName?.Contains(value, StringComparison.OrdinalIgnoreCase) ?? false) ||
        (f.DnsQueryName?.Contains(value, StringComparison.OrdinalIgnoreCase) ?? false) ||
        f.SourcePort?.ToString() == value || f.DestinationPort?.ToString() == value;
}
