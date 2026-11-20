using Upuaut.Core.Models;
using Upuaut.Weigher.Services;

namespace Upuaut.Tests;

public class WeigherEngineTests
{
    private readonly WeigherEngine _engine = new();

    [Fact]
    public void Correlate_MatchesNearestPacketWithinTemporalWindow()
    {
        var baseTime = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

        var log = new LogRecord
        {
            RecordId = 101,
            EventId = 1000,
            ProviderName = "Application Error",
            Channel = "Application",
            Level = LogSeverityLevel.Error,
            Timestamp = baseTime,
            Message = "Service crash connecting to 192.168.1.50:8080",
            ProcessId = 4412
        };

        var nearbyPacket = new PacketFrame
        {
            Timestamp = baseTime.AddMilliseconds(250),
            SourceIp = "192.168.1.10",
            DestinationIp = "192.168.1.50",
            SourcePort = 51234,
            DestinationPort = 8080,
            Protocol = NetworkProtocol.TCP,
            TransportProtocol = NetworkProtocol.TCP,
            ProcessId = 4412,
            ProcessName = "crashapp.exe",
            Summary = "TCP 51234 -> 8080 [RST, ACK]"
        };

        var distantPacket = new PacketFrame
        {
            Timestamp = baseTime.AddSeconds(10), // Outside 2500ms window
            SourceIp = "192.168.1.10",
            DestinationIp = "1.1.1.1",
            Protocol = NetworkProtocol.UDP,
            Summary = "DNS query"
        };

        var results = _engine.Correlate(new[] { log }, new[] { distantPacket, nearbyPacket });

        Assert.Single(results);
        var item = results[0];
        Assert.NotNull(item.NearestPacket);
        Assert.Equal(NetworkProtocol.TCP, item.NearestPacket.Protocol);
        Assert.Equal(250, item.TimeDelta!.Value.TotalMilliseconds);
        Assert.Equal(1, item.NearbyPacketCount);
        Assert.True(item.ProximityScore >= 80);
        Assert.Contains(item.PacketMatchBasis, b => b.Contains("4412"));
        Assert.Contains(item.PacketMatchBasis, b => b.Contains("192.168.1.50"));
    }

    [Fact]
    public void Correlate_FindsNearestRelatedSiblingLog()
    {
        var baseTime = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

        var primaryLog = new LogRecord
        {
            RecordId = 1,
            EventId = 7001,
            ProviderName = "Service Control Manager",
            Channel = "System",
            Level = LogSeverityLevel.Error,
            Timestamp = baseTime,
            Message = "Service failed unexpectedly."
        };

        var relatedLog = new LogRecord
        {
            RecordId = 2,
            EventId = 1000,
            ProviderName = "Application Error",
            Channel = "Application",
            Level = LogSeverityLevel.Error,
            Timestamp = baseTime.AddMilliseconds(-150),
            Message = "Faulting application name: svc.exe"
        };

        var results = _engine.Correlate(new[] { primaryLog, relatedLog }, Array.Empty<PacketFrame>());

        Assert.Equal(2, results.Count);
        var primaryItem = results.First(r => r.Log.RecordId == 1);
        Assert.NotNull(primaryItem.NearestRelatedLog);
        Assert.Equal(2, primaryItem.NearestRelatedLog.RecordId);
        Assert.Equal(-150, primaryItem.RelatedLogDelta!.Value.TotalMilliseconds);
    }

    [Fact]
    public void Analyze_ProducesHighLevelCorrelatedEvents()
    {
        var baseTime = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

        var log = new LogRecord
        {
            RecordId = 42,
            EventId = 4625,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            Channel = "Security",
            Level = LogSeverityLevel.Warning,
            Timestamp = baseTime,
            Message = "An account failed to log on."
        };

        var packet = new PacketFrame
        {
            Timestamp = baseTime.AddMilliseconds(50),
            SourceIp = "10.0.0.99",
            DestinationIp = "10.0.0.1",
            SourcePort = 445,
            DestinationPort = 59850,
            Protocol = NetworkProtocol.TCP,
            Summary = "SMB2 Session Setup Request"
        };

        var events = _engine.Analyze(new[] { log }, new[] { packet }, TimeSpan.FromSeconds(2));

        Assert.Single(events);
        var evt = events[0];
        Assert.Equal(LogSeverityLevel.Warning, evt.Severity);
        Assert.Contains("Event 4625", evt.Title);
        Assert.Contains("10.0.0.99", evt.RootCauseHint);
        Assert.Same(log, evt.LogSource);
        Assert.Same(packet, evt.PacketSource);
    }

    [Fact]
    public void ExportAndDeserializeCaseJson_RoundtripsAccuratelyAndStripsRawBytes()
    {
        var log = new LogRecord
        {
            RecordId = 1,
            ProviderName = "TestProvider",
            Channel = "System",
            Timestamp = DateTime.UtcNow
        };

        var packetWithBytes = new PacketFrame
        {
            Timestamp = DateTime.UtcNow,
            Protocol = NetworkProtocol.TCP,
            SourceIp = "127.0.0.1",
            DestinationIp = "127.0.0.1",
            RawData = new byte[] { 0x01, 0x02, 0x03, 0x04 },
            Payload = new byte[] { 0xAA, 0xBB }
        };

        var item = new TriageItem(
            Log: log,
            NearestPacket: packetWithBytes,
            TimeDelta: TimeSpan.FromMilliseconds(10),
            NearbyPacketCount: 1,
            ProximityScore: 99);

        var notes = new Dictionary<string, string> { ["System:1:0"] = "Confirmed suspicious activity." };
        var triageCase = new TriageCase(
            DateTimeOffset.UtcNow,
            "Ransomware Triage",
            LogTimeRange.LastHour,
            "System",
            null,
            null,
            150,
            new[] { item },
            notes,
            includeInformational: false);

        var json = _engine.ExportCaseJson(triageCase);

        // Raw byte fields must be stripped out of JSON to save space
        Assert.DoesNotContain("RawData", json);
        Assert.DoesNotContain("Payload", json);

        var deserialized = _engine.DeserializeCaseJson(json);
        Assert.Equal("Ransomware Triage", deserialized.CaseTitle);
        Assert.Equal(150, deserialized.ReviewedPackets);
        Assert.Single(deserialized.Items);
        Assert.Null(deserialized.Items[0].NearestPacket!.RawData);
        Assert.Null(deserialized.Items[0].NearestPacket!.Payload);
        Assert.Equal("Confirmed suspicious activity.", deserialized.Notes["System:1:0"]);
    }

    [Fact]
    public void ExportCaseCsv_ProtectsAgainstFormulaInjection()
    {
        var maliciousLog = new LogRecord
        {
            RecordId = 1,
            EventId = 100,
            ProviderName = "=cmd|' /C calc'!A0",
            Channel = "+MaliciousChannel",
            Timestamp = DateTime.UtcNow,
            Message = "@SUM(1,2)"
        };

        var item = new TriageItem(
            Log: maliciousLog,
            NearestPacket: null,
            TimeDelta: null,
            NearbyPacketCount: 0,
            ProximityScore: 0);

        var notes = new Dictionary<string, string> { ["+MaliciousChannel:1:100"] = "-2+3*cmd" };

        var csv = _engine.ExportCaseCsv(new[] { item }, notes);
        var lines = csv.Split(Environment.NewLine);

        Assert.True(lines.Length >= 2);
        // Each field starting with =, +, -, or @ must be escaped with a prepended single quote
        Assert.Contains("'+MaliciousChannel", lines[1]);
        Assert.Contains("'=cmd|' /C calc'!A0", lines[1]);
        Assert.Contains("'-2+3*cmd", lines[1]);
    }
}
