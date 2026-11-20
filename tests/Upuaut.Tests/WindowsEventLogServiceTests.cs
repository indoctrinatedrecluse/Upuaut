using System.Collections.Generic;
using Upuaut.Core.Models;
using Upuaut.Chronicles.Services;
using Xunit;

namespace Upuaut.Tests;

public class WindowsEventLogServiceTests
{
    [Fact]
    public void BuildXPathQuery_SingleProvider_GeneratesCorrectClause()
    {
        var filter = new LogFilterOptions
        {
            TimeRange = LogTimeRange.AllTime,
            Levels = new HashSet<LogSeverityLevel>(),
            SelectedProviders = new HashSet<string> { "Service Control Manager" }
        };

        var xPath = WindowsEventLogService.BuildXPathQuery(filter);

        Assert.Equal("*[System[Provider[@Name='Service Control Manager']]]", xPath);
    }

    [Fact]
    public void BuildXPathQuery_MultipleProviders_GeneratesOrDisjunction()
    {
        var filter = new LogFilterOptions
        {
            TimeRange = LogTimeRange.AllTime,
            Levels = new HashSet<LogSeverityLevel>(),
            SelectedProviders = new HashSet<string> { "Microsoft-Windows-Kernel-Power", "Microsoft-Windows-WLAN-AutoConfig" }
        };

        var xPath = WindowsEventLogService.BuildXPathQuery(filter);

        Assert.Equal("*[System[(Provider[@Name='Microsoft-Windows-Kernel-Power'] or Provider[@Name='Microsoft-Windows-WLAN-AutoConfig'])]]", xPath);
    }

    [Fact]
    public void BuildXPathQuery_SingleProviderNameFallback_GeneratesCorrectClause()
    {
        var filter = new LogFilterOptions
        {
            TimeRange = LogTimeRange.AllTime,
            Levels = new HashSet<LogSeverityLevel>(),
            ProviderName = "Disk"
        };

        var xPath = WindowsEventLogService.BuildXPathQuery(filter);

        Assert.Equal("*[System[Provider[@Name='Disk']]]", xPath);
    }

    [Fact]
    public void BuildXPathQuery_CombinedEventIdAndProviders_GeneratesAndConjunction()
    {
        var filter = new LogFilterOptions
        {
            TimeRange = LogTimeRange.AllTime,
            Levels = new HashSet<LogSeverityLevel>(),
            EventId = 7036,
            SelectedProviders = new HashSet<string> { "Service Control Manager", "Application Error" }
        };

        var xPath = WindowsEventLogService.BuildXPathQuery(filter);

        Assert.Equal("*[System[EventID=7036 and (Provider[@Name='Service Control Manager'] or Provider[@Name='Application Error'])]]", xPath);
    }

    [Fact]
    public void BuildXPathQuery_EmptyFilter_ReturnsWildcard()
    {
        var filter = new LogFilterOptions
        {
            TimeRange = LogTimeRange.AllTime,
            Levels = new HashSet<LogSeverityLevel>()
        };

        var xPath = WindowsEventLogService.BuildXPathQuery(filter);

        Assert.Equal("*", xPath);
    }
}
