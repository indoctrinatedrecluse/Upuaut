using Upuaut.Chronicles.Explorers;
using Upuaut.Chronicles.Services;
using Upuaut.Core.Models;
using Xunit;

namespace Upuaut.Tests;

public class ExplanationEngineTests
{
    private readonly LogExplanationEngine _engine = new();

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
        // On any normal Windows machine with events in the last 7 days, logs should be returned
        if (logs.Count > 0)
        {
            var first = logs[0];
            Assert.True(first.EventId > 0);
            Assert.NotEmpty(first.ProviderName);
            Assert.NotNull(first.Explanation);
        }
    }
}
