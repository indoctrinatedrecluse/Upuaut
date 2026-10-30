using System.Diagnostics.Eventing.Reader;
using System.Text;
using Upuaut.Chronicles.Analytics;
using Upuaut.Chronicles.Explorers;
using Upuaut.Chronicles.Export;
using Upuaut.Chronicles.Parsers;
using Upuaut.Core.Interfaces;
using Upuaut.Core.Models;

namespace Upuaut.Chronicles.Services;

public class WindowsEventLogService : IChroniclesService, IDisposable
{
    private readonly LogExplanationEngine _explanationEngine = new();
    private readonly EventClusterer _clusterer = new();
    private readonly LogExportService _exportService = new();

    private EventLogWatcher? _activeWatcher;
    private bool _isLiveTracing;

    public bool IsLiveTracing => _isLiveTracing;

    public event EventHandler<LogRecord>? LogReceived;
    public event EventHandler<string>? StatusChanged;

    private static readonly string[] StandardChannels = new[]
    {
        "System",
        "Application",
        "Security",
        "Setup",
        "Microsoft-Windows-Diagnostics-Networking/Operational",
        "Microsoft-Windows-DNS-Client/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-User Profile Service/Operational",
        "Microsoft-Windows-WindowsUpdateClient/Operational",
        "Microsoft-Windows-WHEA-Logger/Operational"
    };

    public IReadOnlyList<string> GetAvailableChannels()
    {
        try
        {
            var session = new EventLogSession();
            var allNames = session.GetLogNames().ToList();
            
            var result = new List<string>(StandardChannels.Where(c => allNames.Contains(c, StringComparer.OrdinalIgnoreCase)));
            return result.Count > 0 ? result : StandardChannels;
        }
        catch
        {
            return StandardChannels;
        }
    }

    public async Task<IReadOnlyList<LogRecord>> QueryEventLogsAsync(LogFilterOptions filter, CancellationToken cancellationToken = default)
    {
        return await Task.Run<IReadOnlyList<LogRecord>>(() =>
        {
            var xPath = BuildXPathQuery(filter);
            StatusChanged?.Invoke(this, $"Querying '{filter.Channel}' with filter: {xPath}");

            try
            {
                var query = new EventLogQuery(filter.Channel, PathType.LogName, xPath)
                {
                    ReverseDirection = true
                };

                return ExecuteReader(query, filter, null, cancellationToken);
            }
            catch (EventLogNotFoundException)
            {
                StatusChanged?.Invoke(this, $"Channel '{filter.Channel}' not found on this system.");
                return Array.Empty<LogRecord>();
            }
            catch (UnauthorizedAccessException)
            {
                StatusChanged?.Invoke(this, $"Access denied reading '{filter.Channel}'. Administrator elevation required.");
                return Array.Empty<LogRecord>();
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Error querying '{filter.Channel}': {ex.Message}");
                return Array.Empty<LogRecord>();
            }
        }, cancellationToken);
    }

    public async Task<IReadOnlyList<LogRecord>> LoadEvtxFileAsync(string filePath, LogFilterOptions filter, CancellationToken cancellationToken = default)
    {
        return await Task.Run<IReadOnlyList<LogRecord>>(() =>
        {
            if (!File.Exists(filePath))
            {
                StatusChanged?.Invoke(this, $"File not found: {filePath}");
                return Array.Empty<LogRecord>();
            }

            var xPath = BuildXPathQuery(filter);
            StatusChanged?.Invoke(this, $"Parsing offline EVTX file '{Path.GetFileName(filePath)}'...");

            try
            {
                var query = new EventLogQuery(filePath, PathType.FilePath, xPath)
                {
                    ReverseDirection = true
                };

                return ExecuteReader(query, filter, filePath, cancellationToken);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Failed to parse EVTX file: {ex.Message}");
                return Array.Empty<LogRecord>();
            }
        }, cancellationToken);
    }

    private List<LogRecord> ExecuteReader(EventLogQuery query, LogFilterOptions filter, string? sourceFile, CancellationToken cancellationToken)
    {
        var results = new List<LogRecord>();
        using var reader = new EventLogReader(query);
        long recordIndex = 0;

        while (reader.ReadEvent() is { } record)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (record)
            {
                var logRecord = ConvertEventRecord(record, ++recordIndex, sourceFile);

                // Provider Facet Filter
                if (filter.SelectedProviders != null && filter.SelectedProviders.Count > 0)
                {
                    if (!filter.SelectedProviders.Contains(logRecord.ProviderName))
                    {
                        continue;
                    }
                }

                // Free-text Search
                if (!string.IsNullOrWhiteSpace(filter.SearchText))
                {
                    var search = filter.SearchText.Trim();
                    var matchesSearch =
                        logRecord.Message.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                        logRecord.ProviderName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                        logRecord.EventId.ToString().Contains(search) ||
                        (logRecord.Explanation?.Summary.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                        (logRecord.Explanation?.DecodedStatusCode?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                        (logRecord.RawXml?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false);

                    if (!matchesSearch)
                    {
                        continue;
                    }
                }

                results.Add(logRecord);

                if (results.Count >= filter.MaxEvents)
                {
                    break;
                }
            }
        }

        var sourceName = !string.IsNullOrEmpty(sourceFile) ? Path.GetFileName(sourceFile) : filter.Channel;
        StatusChanged?.Invoke(this, $"Successfully processed {results.Count} events from {sourceName}.");
        return results;
    }

    public Task StartLiveStreamAsync(string channelName, HashSet<LogSeverityLevel> levels, CancellationToken cancellationToken = default)
    {
        StopLiveStreamAsync();

        var filter = new LogFilterOptions
        {
            Channel = channelName,
            Levels = levels,
            TimeRange = LogTimeRange.AllTime
        };

        var xPath = BuildXPathQuery(filter);

        try
        {
            var query = new EventLogQuery(channelName, PathType.LogName, xPath);
            _activeWatcher = new EventLogWatcher(query);
            _activeWatcher.EventRecordWritten += OnEventRecordWritten;
            _activeWatcher.Enabled = true;

            _isLiveTracing = true;
            StatusChanged?.Invoke(this, $"Live streaming active on '{channelName}'");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Failed to start live streaming: {ex.Message}");
        }

        return Task.CompletedTask;
    }

    public Task StopLiveStreamAsync()
    {
        if (_activeWatcher != null)
        {
            _activeWatcher.Enabled = false;
            _activeWatcher.EventRecordWritten -= OnEventRecordWritten;
            _activeWatcher.Dispose();
            _activeWatcher = null;
        }

        _isLiveTracing = false;
        StatusChanged?.Invoke(this, "Live stream paused.");
        return Task.CompletedTask;
    }

    public IReadOnlyList<EventCluster> ClusterLogs(IEnumerable<LogRecord> logs)
    {
        return _clusterer.Cluster(logs);
    }

    public string ExportLogs(IEnumerable<LogRecord> logs, LogExportFormat format)
    {
        return _exportService.Export(logs, format);
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) return;

        try
        {
            var record = ConvertEventRecord(e.EventRecord, DateTime.UtcNow.Ticks, null);
            LogReceived?.Invoke(this, record);
        }
        catch
        {
            // Suppress record conversion exceptions in live stream
        }
    }

    private LogRecord ConvertEventRecord(EventRecord record, long index, string? sourceFile)
    {
        string message;
        try
        {
            message = record.FormatDescription() ?? string.Empty;
        }
        catch
        {
            message = ExtractFallbackMessage(record);
        }

        string? rawXml = null;
        try
        {
            rawXml = record.ToXml();
        }
        catch
        {
            // Ignore XML error
        }

        var properties = new Dictionary<string, string>(EventXmlParser.ExtractProperties(rawXml), StringComparer.OrdinalIgnoreCase);
        // XML usually carries provider names; positional fallback values preserve
        // the parameters when providers omit or vary those names.
        if (record.Properties is not null)
        {
            for (var i = 0; i < record.Properties.Count; i++)
            {
                var key = $"Param{i + 1}";
                if (properties.ContainsKey(key)) continue;
                try
                {
                    var value = record.Properties[i]?.Value?.ToString();
                    if (!string.IsNullOrWhiteSpace(value)) properties[key] = value;
                }
                catch { /* Keep the remaining event fields even if one property cannot be read. */ }
            }
        }
        var severity = MapLevel(record.Level);

        var log = new LogRecord
        {
            RecordId = record.RecordId ?? index,
            EventId = record.Id,
            ProviderName = record.ProviderName ?? "Unknown",
            Channel = record.LogName ?? "System",
            Level = severity,
            Timestamp = record.TimeCreated ?? DateTime.UtcNow,
            Message = message,
            ProcessId = record.ProcessId,
            ThreadId = record.ThreadId,
            ComputerName = record.MachineName,
            TaskCategory = record.TaskDisplayName,
            Keywords = string.Join(", ", record.KeywordsDisplayNames ?? Enumerable.Empty<string>()),
            RawXml = rawXml,
            EventData = properties,
            NormalizedEventData = EventXmlParser.NormalizeProperties(properties),
            SourceFile = sourceFile
        };

        return log with { Explanation = _explanationEngine.Explain(log) };
    }

    private static string ExtractFallbackMessage(EventRecord record)
    {
        var sb = new StringBuilder();
        if (record.Properties != null && record.Properties.Count > 0)
        {
            for (int i = 0; i < record.Properties.Count; i++)
            {
                var val = record.Properties[i]?.Value?.ToString();
                if (!string.IsNullOrWhiteSpace(val))
                {
                    if (sb.Length > 0) sb.Append(" | ");
                    sb.Append(val);
                }
            }
        }

        return sb.Length > 0 ? sb.ToString() : $"Event ID {record.Id} logged by {record.ProviderName}.";
    }

    private static string BuildXPathQuery(LogFilterOptions filter)
    {
        var conditions = new List<string>();

        // Levels
        if (filter.Levels.Count > 0 && filter.Levels.Count < 5)
        {
            var levelParts = new List<string>();
            if (filter.Levels.Contains(LogSeverityLevel.Critical)) levelParts.Add("Level=1");
            if (filter.Levels.Contains(LogSeverityLevel.Error)) levelParts.Add("Level=2");
            if (filter.Levels.Contains(LogSeverityLevel.Warning)) levelParts.Add("Level=3");
            if (filter.Levels.Contains(LogSeverityLevel.Information)) levelParts.Add("Level=4");
            if (filter.Levels.Contains(LogSeverityLevel.Verbose)) levelParts.Add("Level=5");

            if (levelParts.Count > 0)
            {
                conditions.Add($"({string.Join(" or ", levelParts)})");
            }
        }

        // Time Range
        if (filter.TimeRange == LogTimeRange.Custom)
        {
            if (filter.CustomStartTime is { } start)
                conditions.Add($"TimeCreated[@SystemTime >= '{System.Security.SecurityElement.Escape(start.ToUniversalTime().ToString("o"))}']");
            if (filter.CustomEndTime is { } end)
                conditions.Add($"TimeCreated[@SystemTime <= '{System.Security.SecurityElement.Escape(end.ToUniversalTime().ToString("o"))}']");
        }
        else if (filter.TimeRange != LogTimeRange.AllTime)
        {
            long ms = filter.TimeRange switch
            {
                LogTimeRange.LastHour => 3600000,
                LogTimeRange.Last24Hours => 86400000,
                LogTimeRange.Last7Days => 604800000,
                LogTimeRange.Last30Days => 2592000000,
                _ => 86400000
            };

            conditions.Add($"TimeCreated[timediff(@SystemTime) <= {ms}]");
        }

        // Event ID
        if (filter.EventId.HasValue)
        {
            conditions.Add($"EventID={filter.EventId.Value}");
        }

        // Provider Name
        if (!string.IsNullOrWhiteSpace(filter.ProviderName))
        {
            conditions.Add($"Provider[@Name={ToXPathLiteral(filter.ProviderName)}]");
        }

        return conditions.Count > 0
            ? $"*[System[{string.Join(" and ", conditions)}]]"
            : "*";
    }

    private static string ToXPathLiteral(string value)
    {
        if (!value.Contains('\'')) return $"'{value}'";
        if (!value.Contains('"')) return $"\"{value}\"";
        var parts = value.Split('\'');
        var args = new List<string>();
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length > 0) args.Add($"'{parts[i]}'");
            if (i < parts.Length - 1) args.Add("\"'\"");
        }
        return $"concat({string.Join(",", args)})";
    }

    private static LogSeverityLevel MapLevel(byte? level)
    {
        return level switch
        {
            1 => LogSeverityLevel.Critical,
            2 => LogSeverityLevel.Error,
            3 => LogSeverityLevel.Warning,
            4 => LogSeverityLevel.Information,
            5 => LogSeverityLevel.Verbose,
            _ => LogSeverityLevel.Information
        };
    }

    public void Dispose()
    {
        StopLiveStreamAsync().GetAwaiter().GetResult();
    }
}
