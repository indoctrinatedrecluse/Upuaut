using Upuaut.Chronicles.Analytics;
using Upuaut.Chronicles.Explorers;
using Upuaut.Chronicles.Export;
using Upuaut.Chronicles.Parsers;
using Upuaut.Chronicles.Services;
using Upuaut.Core.Models;
using Xunit;

namespace Upuaut.Tests;

public class ExplanationEngineTests
{
    private readonly LogExplanationEngine _engine = new();
    private readonly EventClusterer _clusterer = new();
    private readonly LogExportService _exportService = new();

    [Fact]
    public void ExplainsDcom10016_AsBenignNoise()
    {
        var log = new LogRecord
        {
            EventId = 10016,
            ProviderName = "Microsoft-Windows-DistributedCOM",
            Level = LogSeverityLevel.Warning,
            Message = "The application-specific permission settings do not grant Local Activation permission for the COM Server application with CLSID {2593F8B9-4EAF-457C-B68A-50F6B8EA6B54}..."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.BenignNoise, explanation.TriageRating);
        Assert.True(explanation.IsCuratedKnowledge);
        Assert.Contains("No action required", explanation.RecommendedActions[0]);
    }

    [Fact]
    public void ExplainsKernelPower41_AsCritical()
    {
        var log = new LogRecord
        {
            EventId = 41,
            ProviderName = "Microsoft-Windows-Kernel-Power",
            Level = LogSeverityLevel.Critical,
            Message = "The system has rebooted without cleanly shutting down first."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.Critical, explanation.TriageRating);
        Assert.True(explanation.IsCuratedKnowledge);
        Assert.Contains(explanation.ProbableCauses, c => c.Contains("Power Supply", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ExplainsHal21_WithDecodedStatusNotSupported()
    {
        var log = new LogRecord
        {
            EventId = 21,
            ProviderName = "Microsoft-Windows-HAL",
            Level = LogSeverityLevel.Error,
            Message = "The hardware real-time clock was not set because evaluation of the ACPI Time and Alarm Device method failed. Status: 0xC00000BB."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.BenignNoise, explanation.TriageRating);
        Assert.Contains("ACPI", explanation.Summary);
    }

    [Fact]
    public void ExplainsSecurity4625_WithSubStatusWrongPassword()
    {
        var log = new LogRecord
        {
            EventId = 4625,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            Channel = "Security",
            Level = LogSeverityLevel.Information,
            Message = "An account failed to log on. Subject: Account Name: Administrator. Failure Information: Sub Status: 0xC000006A."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.High, explanation.TriageRating);
        Assert.Contains("STATUS_WRONG_PASSWORD", explanation.Summary);
    }

    [Fact]
    public void ExplainsNtfs55_AsCriticalVolumeCorruption()
    {
        var log = new LogRecord
        {
            EventId = 55,
            ProviderName = "Ntfs",
            Level = LogSeverityLevel.Critical,
            Message = "A corruption was discovered in the file system structure on volume C:."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.Critical, explanation.TriageRating);
        Assert.Contains("chkdsk", explanation.RecommendedActions[0]);
    }

    [Fact]
    public void ExplainsDotNetRuntime1026_AsHighSeverityUnhandledException()
    {
        var log = new LogRecord
        {
            EventId = 1026,
            ProviderName = ".NET Runtime",
            Level = LogSeverityLevel.Error,
            Message = "Application: Upuaut.exe Framework Version: v4.0.30319 Description: The process was terminated due to an unhandled exception."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.High, explanation.TriageRating);
        Assert.True(explanation.IsCuratedKnowledge);
        Assert.Contains(".NET", explanation.Summary);
    }

    [Fact]
    public void ExplainsWinlogon4005_AsCriticalLogonCrash()
    {
        var log = new LogRecord
        {
            EventId = 4005,
            ProviderName = "Microsoft-Windows-Winlogon",
            Level = LogSeverityLevel.Error,
            Message = "The Windows logon process has unexpectedly terminated."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal(TriageSeverity.Critical, explanation.TriageRating);
        Assert.Contains("logon", explanation.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecodesArbitraryStatusCode_AccessViolation()
    {
        var log = new LogRecord
        {
            EventId = 9999,
            ProviderName = "CustomApplication",
            Level = LogSeverityLevel.Error,
            Message = "Failed executing task due to internal error 0xC0000005 occurred during processing."
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.NotNull(explanation.DecodedStatusCode);
        Assert.Contains("STATUS_ACCESS_VIOLATION", explanation.DecodedStatusCode);
        Assert.Equal("The software attempted to read or write to an invalid memory address.", explanation.StatusMeaning);
    }

    [Fact]
    public void EventClusterer_DeduplicatesRepetitiveEvents()
    {
        var now = DateTime.UtcNow;
        var logs = new List<LogRecord>();

        // 50 repetitive service timeout events
        for (int i = 0; i < 50; i++)
        {
            logs.Add(new LogRecord
            {
                RecordId = i + 1,
                EventId = 7009,
                ProviderName = "Service Control Manager",
                Level = LogSeverityLevel.Error,
                Timestamp = now.AddSeconds(i * 10),
                Message = "A timeout was reached (30000 milliseconds) while waiting for the TestService service to connect.",
                ProcessId = 1200
            });
        }

        // 10 DNS timeout events
        for (int i = 0; i < 10; i++)
        {
            logs.Add(new LogRecord
            {
                RecordId = i + 100,
                EventId = 1014,
                ProviderName = "Microsoft-Windows-DNS-Client",
                Level = LogSeverityLevel.Warning,
                Timestamp = now.AddSeconds(i * 30),
                Message = "Name resolution for the name api.internal.corp timed out after none of the configured DNS servers responded."
            });
        }

        var clusters = _clusterer.Cluster(logs);

        Assert.Equal(2, clusters.Count);
        var scmCluster = clusters.First(c => c.EventId == 7009);
        Assert.Equal(50, scmCluster.Count);
        Assert.Contains("1200", scmCluster.DistinctProcesses);

        var dnsCluster = clusters.First(c => c.EventId == 1014);
        Assert.Equal(10, dnsCluster.Count);
    }

    [Fact]
    public void EventXmlParser_ExtractsNamedProperties()
    {
        var xml = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                      <System>
                        <Provider Name='Microsoft-Windows-Security-Auditing' />
                        <EventID>4625</EventID>
                      </System>
                      <EventData>
                        <Data Name='SubjectUserName'>SYSTEM</Data>
                        <Data Name='TargetUserName'>JohnDoe</Data>
                        <Data Name='Status'>0xc000006d</Data>
                        <Data Name='SubStatus'>0xc000006a</Data>
                        <Data Name='IpAddress'>192.168.1.50</Data>
                      </EventData>
                    </Event>";

        var props = EventXmlParser.ExtractProperties(xml);

        Assert.Equal(5, props.Count);
        Assert.Equal("JohnDoe", props["TargetUserName"]);
        Assert.Equal("192.168.1.50", props["IpAddress"]);
        Assert.Equal("0xc000006a", props["SubStatus"]);
    }

    [Fact]
    public void LogExportService_GeneratesMarkdownAndCsv()
    {
        var logs = new List<LogRecord>
        {
            new()
            {
                EventId = 41,
                ProviderName = "Microsoft-Windows-Kernel-Power",
                Level = LogSeverityLevel.Critical,
                Message = "The system has rebooted without cleanly shutting down first.",
                Explanation = new LogExplanation
                {
                    Summary = "The computer rebooted without cleanly shutting down first.",
                    TriageRating = TriageSeverity.Critical
                }
            }
        };

        var md = _exportService.Export(logs, LogExportFormat.Markdown);
        Assert.Contains("# 🐺 Upuaut Diagnostic Triage Report", md);
        Assert.Contains("Critical Issues", md);

        var csv = _exportService.Export(logs, LogExportFormat.Csv);
        Assert.Contains("Kernel-Power", csv);
        Assert.Contains("Critical", csv);
    }

    [Fact]
    public async Task QueryEventLogs_QueriesRealWindowsSystemLog()
    {
        using var service = new WindowsEventLogService();
        var filter = new LogFilterOptions
        {
            Channel = "System",
            Levels = new HashSet<LogSeverityLevel> { LogSeverityLevel.Critical, LogSeverityLevel.Error, LogSeverityLevel.Warning },
            TimeRange = LogTimeRange.Last7Days,
            MaxEvents = 10
        };

        var logs = await service.QueryEventLogsAsync(filter);

        Assert.NotNull(logs);
        if (logs.Count > 0)
        {
            var first = logs[0];
            Assert.True(first.EventId > 0);
            Assert.NotEmpty(first.ProviderName);
            Assert.NotNull(first.Explanation);
        }
    }

    [Fact]
    public void ForensicDecoder_DecodesBugcheckCodeDecimal278_AsVideoTdrFailure()
    {
        var log = new LogRecord
        {
            EventId = 1001,
            ProviderName = "Microsoft-Windows-WER-SystemErrorReporting",
            Channel = "System",
            Level = LogSeverityLevel.Critical,
            Message = "The computer has rebooted from a bugcheck.",
            EventData = new Dictionary<string, string>
            {
                { "BugcheckCode", "278" },
                { "DumpFile", @"C:\Windows\Minidump\020126-10234-01.dmp" }
            }
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.NotNull(explanation.DecodedFields);
        Assert.Equal("VIDEO_TDR_FAILURE", explanation.DecodedFields["Stop Error Name"]);
        Assert.Contains("display driver", explanation.DecodedFields["Meaning"], StringComparison.OrdinalIgnoreCase);
        Assert.Equal(@"C:\Windows\Minidump\020126-10234-01.dmp", explanation.DecodedFields["Dump File Location"]);
    }

    [Fact]
    public void ForensicDecoder_DecodesApplicationError1000_WithModuleAndAccessViolation()
    {
        var log = new LogRecord
        {
            EventId = 1000,
            ProviderName = "Application Error",
            Channel = "Application",
            Level = LogSeverityLevel.Error,
            Message = "Faulting application name: GameClient.exe, faulting module name: d3d11.dll",
            EventData = new Dictionary<string, string>
            {
                { "FaultingApplicationName", "GameClient.exe" },
                { "FaultingModuleName", "d3d11.dll" },
                { "ExceptionCode", "0xc0000005" },
                { "FaultOffset", "0x000000000018a42b" }
            }
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal("GameClient.exe", explanation.DecodedFields["Crashing App"]);
        Assert.Equal("d3d11.dll", explanation.DecodedFields["Faulting Module"]);
        Assert.Contains("DirectX 11", explanation.DecodedFields["Module Identity"]);
        Assert.Contains("STATUS_ACCESS_VIOLATION", explanation.DecodedFields["Exception Meaning"]);
    }

    [Fact]
    public void ForensicDecoder_DecodesServiceControlManager7000_WithExitCode1060()
    {
        var log = new LogRecord
        {
            EventId = 7000,
            ProviderName = "Service Control Manager",
            Channel = "System",
            Level = LogSeverityLevel.Error,
            Message = "The OldLegacyService service failed to start due to the following error: The specified service does not exist as an installed service.",
            EventData = new Dictionary<string, string>
            {
                { "param1", "OldLegacyService" },
                { "param2", "1060" }
            }
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal("OldLegacyService", explanation.DecodedFields["Service Identifier"]);
        Assert.Contains("ERROR_SERVICE_DOES_NOT_EXIST", explanation.DecodedFields["SCM Error Code"]);
    }

    [Fact]
    public void ForensicDecoder_DecodesSecurity4625_WithLogonType10AndSubStatus()
    {
        var log = new LogRecord
        {
            EventId = 4625,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            Channel = "Security",
            Level = LogSeverityLevel.Information,
            Message = "An account failed to log on.",
            EventData = new Dictionary<string, string>
            {
                { "TargetUserName", "Administrator" },
                { "LogonType", "10" },
                { "SubStatus", "0xC000006A" },
                { "IpAddress", "192.168.1.150" }
            }
        };

        var explanation = _engine.Explain(log);

        Assert.NotNull(explanation);
        Assert.Equal("Administrator", explanation.DecodedFields["Target Account"]);
        Assert.Contains("Remote Desktop Protocol", explanation.DecodedFields["Logon Type"]);
        Assert.Contains("STATUS_WRONG_PASSWORD", explanation.DecodedFields["SubStatus Explanation"]);
        Assert.Equal("192.168.1.150", explanation.DecodedFields["Source IP Address"]);
    }
}
