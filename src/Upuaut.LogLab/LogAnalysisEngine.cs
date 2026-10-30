using System.Text;
using Upuaut.LogLab.Models;

namespace Upuaut.LogLab;

/// <summary>Deterministic, evidence-grounded scenario labeling for parsed log entries.</summary>
public sealed class LogAnalysisEngine : ILogAnalysisEngine
{
    private sealed record Rule(
        LogScenarioCategory Category,
        string Headline,
        string Explanation,
        string[] Signals,
        string[] Tags,
        string[] Recommendations,
        string? Source = null,
        string? KnowledgeId = null);

    private static readonly Rule[] Rules =
    [
        .. LogKnowledgeBase.GetBuiltInPatterns().Select(pattern => new Rule(pattern.Category, pattern.Headline, pattern.Explanation,
            pattern.Signals.ToArray(), pattern.Tags.ToArray(), pattern.Recommendations.ToArray(), pattern.SourceUrl, pattern.Id)),
        // Source-backed signatures are deliberately phrased as observations, not root-cause claims.
        new(LogScenarioCategory.Performance, "Container terminated by its memory limit", "Kubernetes reports OOMKilled when a container is terminated after exceeding its memory limit. This identifies the termination signal; inspect the container's prior memory use and restart history before changing limits.",
            ["oomkilled", "reason: oomkilled", "last state: terminated"], ["kubernetes", "container", "memory", "termination"], ["Inspect the Pod status, restart count, memory limit, and nearby node pressure events.", "Compare memory use over time and review application allocation behavior before adjusting a resource limit."], "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/", "kubernetes.oomkilled"),
        new(LogScenarioCategory.Service, "Kubernetes container restart loop", "CrashLoopBackOff is a restart backoff state, not a diagnosis. The container has repeatedly terminated; the previous container logs and termination reason usually provide stronger evidence.",
            ["crashloopbackoff", "back-off restarting failed container"], ["kubernetes", "container", "restart-loop"], ["Inspect the previous container instance's logs and termination reason, then review Pod events and probe results.", "Check recent configuration, image, dependency, and resource changes around the first restart."], "https://kubernetes.io/docs/tasks/debug/", "kubernetes.crashloopbackoff"),
        new(LogScenarioCategory.Network, "Kubernetes image pull failed", "ImagePullBackOff or ErrImagePull indicates Kubernetes could not obtain the requested container image. The event text may distinguish a missing tag, registry connectivity, or authentication issue.",
            ["imagepullbackoff", "errimagepull", "failed to pull image", "pull access denied"], ["kubernetes", "container-image", "registry"], ["Check the exact image name and tag, Pod events, registry reachability, and image-pull secret reference.", "Use the detailed registry error to distinguish an absent image from denied access or a transport failure."], "https://kubernetes.io/docs/tasks/debug/", "kubernetes.image-pull"),
        new(LogScenarioCategory.Service, "systemd could not execute the service process", "systemd status 203/EXEC means the requested process could not be executed. Common checks include the executable path, file permissions, interpreter, and filesystem mount options.",
            ["status=203/exec", "exit_exec", "failed at step exec"], ["systemd", "service", "process-launch"], ["Inspect ExecStart and verify the target exists and is executable by the configured service user.", "Check the interpreter or shebang, parent-directory access, and mount policy without weakening system-wide security."], "https://freedesktop.org/software/systemd/man/latest/systemd.exec.html", "systemd.exit-exec"),
        new(LogScenarioCategory.Failure, "PostgreSQL duplicate-key constraint violation", "SQLSTATE 23505 is PostgreSQL's unique_violation condition. It usually means an attempted row conflicts with a unique constraint; it does not by itself indicate database corruption.",
            ["23505", "unique_violation", "duplicate key value violates unique constraint"], ["postgresql", "sqlstate", "constraint"], ["Inspect the named constraint and key values, then check whether the operation should be an update, upsert, or deduplicated retry.", "Correlate the statement and transaction context while avoiding unnecessary exposure of sensitive key data."], "https://www.postgresql.org/docs/current/errcodes-appendix.html", "postgresql.23505"),
        new(LogScenarioCategory.Performance, "PostgreSQL connection capacity reached", "SQLSTATE 53300 represents too_many_connections. This is evidence that the server's connection capacity was reached at that time, not proof that raising the limit is the right fix.",
            ["53300", "too_many_connections", "sorry, too many clients already"], ["postgresql", "sqlstate", "connections"], ["Review active and idle sessions, connection-pool behavior, and connection churn around the incident.", "Check server capacity and workload before changing connection limits; pool or leak fixes may be safer."], "https://www.postgresql.org/docs/current/errcodes-appendix.html", "postgresql.53300"),
        new(LogScenarioCategory.Failure, "PostgreSQL serialization conflict", "SQLSTATE 40001 indicates a serialization failure. The transaction could not be committed under the selected isolation guarantees and may need a bounded retry of the whole transaction.",
            ["40001", "serialization_failure", "could not serialize access"], ["postgresql", "sqlstate", "transaction"], ["Review transaction boundaries and concurrent changes; retry the complete transaction only when the operation is safe to repeat.", "Look for repeated conflicts or long-running transactions that overlap the affected workload."], "https://www.postgresql.org/docs/current/mvcc-serialization-failure-handling.html", "postgresql.40001"),
        new(LogScenarioCategory.Performance, "MySQL connection limit reached", "MySQL error 1040 (Too many connections) means available client connection slots are in use. Increasing the limit without checking pool leaks or workload can increase server pressure.",
            ["error 1040", "too many connections", "er_con_count_error"], ["mysql", "connections", "capacity"], ["Review connection counts and process lists using an authorized administrative account; look for idle-session buildup and pool churn.", "Compare the configured connection limit with memory capacity and workload before increasing it."], "https://dev.mysql.com/doc/refman/8.0/en/too-many-connections.html", "mysql.1040"),
        new(LogScenarioCategory.Authentication, "MySQL connection authentication denied", "MySQL error 1045 indicates access was denied for the presented account and connection context. The message alone cannot distinguish credentials, account host matching, or authentication configuration.",
            ["error 1045", "er_access_denied_error", "access denied for user"], ["mysql", "authentication", "database"], ["Verify the intended account, host portion, authentication method, and secret source without pasting credentials into reports.", "Compare successful and failed connection context and inspect server-side account grants."], "https://dev.mysql.com/doc/refman/8.0/en/error-access-denied.html", "mysql.1045"),
        new(LogScenarioCategory.Performance, ".NET process ran out of memory", "System.OutOfMemoryException means a managed allocation could not be satisfied. It may reflect process limits, allocation pressure, fragmentation, or an unexpectedly large request; the message alone does not identify which.",
            ["system.outofmemoryexception", "outofmemoryexception", "insufficient memory to continue the execution of the program"], ["dotnet", "memory", "exception"], ["Capture process memory and allocation trends near the event, including container or job memory limits.", "Inspect the allocation path and workload size; avoid increasing limits until the process and host constraints are understood."], "https://learn.microsoft.com/dotnet/api/system.outofmemoryexception", "dotnet.out-of-memory"),
        new(LogScenarioCategory.Performance, "Java virtual machine memory exhaustion", "OutOfMemoryError indicates the JVM could not satisfy a memory need. The subtype (such as Java heap space or Metaspace) narrows the affected area but still requires workload and heap evidence.",
            ["java.lang.outofmemoryerror", "outofmemoryerror: java heap space", "outofmemoryerror: metaspace", "gc overhead limit exceeded"], ["java", "jvm", "memory"], ["Record the exact OutOfMemoryError subtype and inspect heap, garbage-collection, and process/container memory data.", "Review heap dumps or allocation profiles where available before changing heap or container limits."], "https://docs.oracle.com/en/java/javase/", "jvm.out-of-memory"),
        new(LogScenarioCategory.Network, "Web server upstream failure", "HTTP 502, 503, or 504 and upstream errors describe a gateway-to-backend failure path. They do not by themselves establish whether the proxy, network, or upstream application is responsible.",
            ["upstream timed out", "upstream prematurely closed connection", "bad gateway", "http 502", "http 503", "http 504", "gateway timeout"], ["http", "proxy", "upstream"], ["Correlate the request timestamp and upstream address with backend health, latency, and connection-reset logs.", "Check proxy timeout and retry behavior alongside application capacity; avoid masking persistent backend failures with larger timeouts."], "https://nginx.org/en/docs/http/ngx_http_proxy_module.html", "http.upstream-failure"),
        new(LogScenarioCategory.Network, "TLS certificate validation failed", "Certificate validation errors commonly reflect trust-chain, hostname, validity-period, or local clock problems. Do not treat disabling certificate verification as a remediation.",
            ["certificate has expired", "certificate verify failed", "unable to get local issuer certificate", "x509: certificate signed by unknown authority", "hostname mismatch"], ["tls", "certificate", "trust"], ["Inspect the certificate validity interval, subject names, trust chain, and system clock at the affected endpoint.", "Renew or correctly deploy the certificate/CA chain; keep peer verification enabled."], "https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting", "tls.certificate-validation"),
        new(LogScenarioCategory.Network, "DNS name resolution failed", "Name-resolution errors show that the requested name was not resolved by the observed resolver path. Check the queried name, resolver response, and scope before changing DNS settings.",
            ["nxdomain", "name or service not known", "temporary failure in name resolution", "no such host", "getaddrinfo failed"], ["dns", "name-resolution"], ["Capture the queried hostname and resolver response, then compare with authoritative records and another approved resolver.", "Check whether the failure is limited to one client, network, search suffix, or time window."], "https://learn.microsoft.com/windows-server/networking/dns/troubleshoot/troubleshoot-dns-client-resolution-issues", "network.dns-resolution"),
        new(LogScenarioCategory.Storage, "Filesystem or volume is out of space", "ENOSPC or a no-space-left error indicates a write could not obtain required storage. The exhausted resource may be a filesystem, quota, container layer, or inode pool.",
            ["enospc", "no space left on device", "there is not enough space on the disk", "disk quota exceeded"], ["storage", "capacity", "filesystem"], ["Identify the target path and check free bytes, inode availability, quotas, and container ephemeral-storage limits.", "Preserve relevant logs and application data before cleanup; confirm which files are safe to remove."], "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/", "storage.enospc"),
        new(LogScenarioCategory.Service, "Process could not bind to a network address", "Address-already-in-use errors indicate a bind conflict for the reported address and port at that moment. A stale assumption about process ownership can lead to stopping the wrong service.",
            ["address already in use", "eaddrinuse", "only one usage of each socket address", "failed to bind"], ["network", "port-conflict", "service"], ["Identify the exact local address and port and inspect the owning process and its lifecycle.", "Check duplicate instances, service activation, and restart overlap before changing the listening port."], "https://learn.microsoft.com/dotnet/api/system.net.sockets.socketerror", "network.bind-conflict"),
        new(LogScenarioCategory.Crash, "Crash or unhandled-exception signal", "Crash-related language was found in this entry. It identifies a crash signal in the log, not the underlying cause.",
            ["unhandled exception", "segmentation fault", "application crash", "process crashed", "stack trace", "traceback", "core dumped", "fatal exception", "crash"],
            ["process", "exception"], ["Review the surrounding entries for the first failure before this message.", "Inspect any exception type, module, process, or dump reference recorded in the source."]),
        new(LogScenarioCategory.Installation, "Installation or setup activity", "Installation-related terms were found. The entry may describe setup progress, completion, or failure; use its status and nearby entries to establish the outcome.",
            ["installation", "install", "installer", "setup", "msi", "package install", "uninstall"],
            ["setup", "package"], ["Check the installer result code and the first preceding error.", "Compare this step with later rollback, completion, or reboot entries."]),
        new(LogScenarioCategory.Update, "Software update activity", "Update or patch language was found in the entry. The text indicates update activity, not whether the update caused a later issue.",
            ["update", "upgrade", "patch", "rollback", "hotfix"],
            ["update", "deployment"], ["Check the package version and update result recorded nearby.", "Look for rollback, restart-required, or compatibility messages in adjacent entries."]),
        new(LogScenarioCategory.Authentication, "Authentication or sign-in event", "Authentication-related terms were found. Verify the identity, authentication method, and result in the original record.",
            ["authentication failed", "authentication failure", "failed to authenticate", "failed password", "account locked", "login failed", "logon failure", "invalid password", "invalid credentials", "token expired", "sign-in failed"],
            ["identity", "authentication"], ["Check the account, authentication method, and exact result code.", "Review nearby lockout, token-renewal, or identity-provider events."]),
        new(LogScenarioCategory.Security, "Security or access-control event", "Security or access-control language was found. This label does not establish whether the activity was malicious.",
            ["access denied", "permission denied", "unauthorized", "blocked by policy", "security alert", "intrusion", "certificate validation failed", "firewall blocked"],
            ["access-control", "security"], ["Verify the actor, target resource, and policy or permission named in the source.", "Correlate with adjacent audit events before treating this as suspicious activity."]),
        new(LogScenarioCategory.Network, "Network or name-resolution event", "Network-related terms were found. The record points to a connectivity or protocol event but does not identify where the fault lies.",
            ["connection timed out", "request timed out", "upstream connection", "upstream", "connection refused", "network unreachable", "host not found", "name resolution", "dns", "socket error", "handshake failed", "connection reset", "http 503", "http 502", "http 504", "http 5", "httpstatus", "http status", "endpoint"],
            ["connectivity", "network"], ["Check the remote endpoint, port, and timestamp captured in the entry.", "Compare with DNS, firewall, and service-availability records for the same interval."]),
        new(LogScenarioCategory.Storage, "Storage or file-system event", "Storage-related terms were found. Confirm the affected volume or path and the exact operation in the source.",
            ["disk full", "no space left", "i/o error", "read-only file system", "write failed", "disk error", "volume", "filesystem", "file system"],
            ["storage", "filesystem"], ["Identify the affected volume or path and check available space and health records.", "Review nearby read, write, retry, and device-reset messages."]),
        new(LogScenarioCategory.Service, "Service or background-process event", "Service lifecycle language was found. Check the service name and result before inferring impact.",
            ["failed to start service", "service failed", "service stopped", "service started", "service exited", "service recovered", "service restarted", "automatic restart", "daemon", "unit entered failed", "service restart"],
            ["service", "lifecycle"], ["Check the named service, its exit code, and its dependency state.", "Inspect entries immediately before the stop or restart for a triggering error."]),
        new(LogScenarioCategory.Performance, "Performance or resource-pressure event", "Performance or resource-pressure language was found. The entry alone does not show whether the condition was sustained or user-visible.",
            ["out of memory", "memory pressure", "resource exhausted", "high latency", "slow response", "deadlock detected", "deadlock victim", "deadlock", "cpu usage", "timed out", "timeout"],
            ["performance", "resource"], ["Check duration, affected component, and whether the condition repeats.", "Compare resource metrics with nearby workload and service events."]),
        new(LogScenarioCategory.Maintenance, "Maintenance or health-check activity", "Maintenance-related terms were found. Confirm whether the task completed and whether it reported affected items.",
            ["backup", "restore", "cleanup", "maintenance", "health check", "scheduled task", "scan completed", "integrity check"],
            ["maintenance", "scheduled-work"], ["Review the task result and any skipped or failed items.", "Compare the recorded task time with the system or application changes under investigation."]),
        new(LogScenarioCategory.Success, "Successful operation signal", "Completion or health language was found. Treat this as a reported success for this step only.",
            ["completed successfully", "successfully completed", "operation completed", "started successfully", "healthy", "passed", "succeeded"],
            ["success", "completion"], ["Check that a later entry confirms the full workflow completed.", "If investigating a failure, use the timestamp and component to compare this step with the first error."])
    ];
    private static readonly IReadOnlyDictionary<string, double> SignalIdf = BuildSignalIdf();

    public LogAnalysisReport Analyze(LogDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var analyses = new Dictionary<int, LogEntryAnalysis>(document.Entries.Count);
        var counts = new Dictionary<LogScenarioCategory, int>();
        var errors = 0;
        var warnings = 0;

        foreach (var entry in document.Entries)
        {
            var analysis = document.ContentKind == LogContentKind.BinaryLike
                ? new LogEntryAnalysis(entry.Index, LogScenarioCategory.Unclassified, "Binary-like data preview", "Scenario classification was skipped because this file is predominantly non-text or encrypted. Use the decoded raw preview for manual inspection.", RuleMatchStrength.NoRuleMatched, ["binary-like"], [], [])
                : Classify(entry);
            analyses[entry.Index] = analysis;
            counts[analysis.Category] = counts.GetValueOrDefault(analysis.Category) + 1;
            if (document.ContentKind != LogContentKind.BinaryLike)
            {
                if (entry.Severity is LogEntrySeverity.Error or LogEntrySeverity.Critical) errors++;
                if (entry.Severity == LogEntrySeverity.Warning) warnings++;
            }
        }

        var classified = analyses.Values.Count(result => result.Category != LogScenarioCategory.Unclassified);
        var categoryCounts = counts.OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key)
            .Select(pair => new LogCategoryCount(pair.Key, pair.Value)).ToArray();
        return new LogAnalysisReport(document.Entries.Count, classified, errors, warnings, categoryCounts, analyses);
    }

    private static LogEntryAnalysis Classify(ParsedLogEntry entry)
    {
        var text = BuildSearchText(entry);
        Rule? bestRule = null;
        string[] bestMatches = [];
        var bestScore = 0d;
        foreach (var rule in Rules)
        {
            var found = rule.Signals.Where(signal => text.Contains(signal, StringComparison.OrdinalIgnoreCase)).ToArray();
            var matches = found.Where(signal => !found.Any(other => other.Length > signal.Length && other.Contains(signal, StringComparison.OrdinalIgnoreCase))).ToArray();
            // BM25-inspired inverse document frequency: uncommon codes and phrases carry more weight
            // than generic words repeated across many knowledge patterns.
            var score = matches.Sum(signal => 8d + SignalTokens(signal).Sum(term => SignalIdf.GetValueOrDefault(term, 0.5) * 2.5)) + Math.Min(matches.Length, 5) * 4d;
            if (score > bestScore) { bestRule = rule; bestMatches = matches; bestScore = score; }
        }

        if (bestRule is null)
        {
            var category = entry.Severity switch
            {
                LogEntrySeverity.Critical => LogScenarioCategory.Failure,
                LogEntrySeverity.Error => LogScenarioCategory.Failure,
                LogEntrySeverity.Warning => LogScenarioCategory.Warning,
                LogEntrySeverity.Success => LogScenarioCategory.Success,
                LogEntrySeverity.Trace or LogEntrySeverity.Debug or LogEntrySeverity.Information => LogScenarioCategory.Operational,
                _ => LogScenarioCategory.Unclassified
            };
            var headline = category switch
            {
                LogScenarioCategory.Failure when entry.Severity == LogEntrySeverity.Critical => "Critical-severity entry (crash not confirmed)",
                LogScenarioCategory.Failure => "Error entry without a specific scenario match",
                LogScenarioCategory.Warning => "Warning entry without a specific scenario match",
                LogScenarioCategory.Success => "Success-level entry",
                LogScenarioCategory.Operational => "Operational log entry",
                _ => "No scenario pattern recognized"
            };
            var explanation = category == LogScenarioCategory.Unclassified
                ? "No supported scenario phrase or recognized severity was found. The entry remains available for manual review."
                : $"No specific scenario rule matched. The entry was grouped using its parsed severity ({entry.Severity}); review the raw source for context.";
            return new LogEntryAnalysis(entry.Index, category, headline, explanation, RuleMatchStrength.NoRuleMatched,
                BuildTags(category, entry.Severity, []), BuildEvidence(entry, []), GenericRecommendations(category));
        }

        var strength = bestMatches.Length >= 3 ? RuleMatchStrength.Strong : bestMatches.Length == 2 ? RuleMatchStrength.Moderate : RuleMatchStrength.Weak;
        var evidence = BuildEvidence(entry, bestMatches);
        var explanationText = $"Matched signal(s): {string.Join(", ", bestMatches)}. {bestRule.Explanation}";
        return new LogEntryAnalysis(entry.Index, bestRule.Category, bestRule.Headline, explanationText, strength,
            BuildTags(bestRule.Category, entry.Severity, bestMatches).Concat(bestRule.KnowledgeId is null ? [] : [$"knowledge:{bestRule.KnowledgeId}"]).ToArray(), evidence, bestRule.Recommendations)
        {
            KnowledgeId = bestRule.KnowledgeId,
            KnowledgeSource = bestRule.Source
        };
    }

    private static IReadOnlyDictionary<string, double> BuildSignalIdf()
    {
        var ruleTerms = Rules.Select(rule => rule.Signals.SelectMany(SignalTokens).ToHashSet(StringComparer.OrdinalIgnoreCase)).ToArray();
        var count = Math.Max(1, ruleTerms.Length);
        var documentFrequency = ruleTerms.SelectMany(terms => terms).GroupBy(term => term, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        return documentFrequency.ToDictionary(pair => pair.Key, pair => Math.Log(1d + (count - pair.Value + 0.5d) / (pair.Value + 0.5d)), StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SignalTokens(string signal)
    {
        var token = new StringBuilder();
        foreach (var character in signal)
        {
            if (char.IsLetterOrDigit(character)) token.Append(char.ToLowerInvariant(character));
            else if (token.Length > 0) { yield return token.ToString(); token.Clear(); }
        }
        if (token.Length > 0) yield return token.ToString();
    }

    private static string BuildSearchText(ParsedLogEntry entry)
    {
        var builder = new StringBuilder(Math.Min(8192, entry.Message.Length + 256));
        AppendBounded(builder, entry.Message, 4096);
        AppendBounded(builder, entry.Source, 256);
        foreach (var (key, value) in entry.Fields.Take(32))
        {
            AppendBounded(builder, key, 96);
            AppendBounded(builder, value, 256);
            if (builder.Length >= 8192) break;
        }
        return builder.ToString();
    }

    private static void AppendBounded(StringBuilder builder, string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || builder.Length >= 8192) return;
        builder.Append(' ').Append(value.AsSpan(0, Math.Min(value.Length, maxLength)));
    }

    private static IReadOnlyList<LogEvidence> BuildEvidence(ParsedLogEntry entry, IReadOnlyList<string> signals)
    {
        var evidence = new List<LogEvidence>();
        foreach (var signal in signals.Take(4))
        {
            var field = entry.Fields.FirstOrDefault(pair => pair.Value.Contains(signal, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(field.Key)) evidence.Add(new LogEvidence(field.Key, Clip(field.Value)));
            else if (entry.Fields.FirstOrDefault(pair => pair.Key.Contains(signal, StringComparison.OrdinalIgnoreCase)) is { Key.Length: > 0 } namedField)
                evidence.Add(new LogEvidence(namedField.Key, Clip(namedField.Value)));
            else if (entry.Message.Contains(signal, StringComparison.OrdinalIgnoreCase)) evidence.Add(new LogEvidence("Message", Clip(entry.Message)));
            else if (entry.RawText.Contains(signal, StringComparison.OrdinalIgnoreCase))
            {
                var position = entry.RawText.IndexOf(signal, StringComparison.OrdinalIgnoreCase);
                var start = Math.Max(0, position - 90);
                var length = Math.Min(240, entry.RawText.Length - start);
                evidence.Add(new LogEvidence("Raw source", Clip(entry.RawText.Substring(start, length))));
            }
            else if (entry.Source?.Contains(signal, StringComparison.OrdinalIgnoreCase) == true) evidence.Add(new LogEvidence("Source", Clip(entry.Source)));
        }
        if (evidence.Count == 0 && !string.IsNullOrWhiteSpace(entry.Message)) evidence.Add(new LogEvidence("Message", Clip(entry.Message)));
        return evidence.DistinctBy(item => (item.Field, item.Value)).ToArray();
    }

    private static IReadOnlyList<string> BuildTags(LogScenarioCategory category, LogEntrySeverity severity, IEnumerable<string> signals)
    {
        var tags = new List<string> { category.ToString().ToLowerInvariant() };
        if (severity != LogEntrySeverity.Unknown) tags.Add(severity.ToString().ToLowerInvariant());
        tags.AddRange(signals.Take(3).Select(signal => signal.Replace(' ', '-')));
        return tags.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IReadOnlyList<string> GenericRecommendations(LogScenarioCategory category) => category switch
    {
        LogScenarioCategory.Failure => ["Inspect the first preceding warning or error and its component.", "Compare the timestamp and event identifier with related records."],
        LogScenarioCategory.Warning => ["Check whether a later entry reports recovery or escalation.", "Review the affected component and neighboring events for context."],
        LogScenarioCategory.Success => ["Confirm a later record reports completion of the full operation."],
        _ => ["Review the raw entry and surrounding lines for context.", "Search for related entries by component, timestamp, or identifier."]
    };

    private static string Clip(string value) => value.Length <= 280 ? value : value[..277] + "...";
}
