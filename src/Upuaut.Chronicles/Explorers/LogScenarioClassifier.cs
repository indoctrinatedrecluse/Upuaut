using System.Text.RegularExpressions;
using Upuaut.Core.Models;

namespace Upuaut.Chronicles.Explorers;

/// <summary>Adds stable, searchable labels and evidence-grounded context to a decoded event.</summary>
internal static class LogScenarioClassifier
{
    private static readonly Regex TagPattern = new("[^a-z0-9]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static LogExplanation Enrich(LogRecord log, LogExplanation explanation)
    {
        var provider = log.ProviderName ?? "Unknown";
        var service = Value(log, "ServiceName", "param1", "Service");
        var app = Value(log, "FaultingApplicationName", "ApplicationName", "AppName");
        var module = Value(log, "FaultingModuleName", "ModuleName");
        var user = Value(log, "TargetUserName", "AccountName", "SubjectUserName");
        var address = Value(log, "IpAddress", "SourceIpAddress", "ClientAddress");
        var status = Value(log, "SubStatus", "Status", "ErrorCode", "ExceptionCode");
        var queryName = Value(log, "QueryName", "Name", "Query");

        var category = ClassifyCategory(log, provider);
        var headline = Headline(log, provider, service, app, module, user, address, queryName, explanation);
        var causes = explanation.ProbableCauses.ToList();
        var actions = explanation.RecommendedActions.ToList();
        var evidence = new List<EvidenceObservation>
        {
            new("Provider", provider, "Identifies the Windows component that emitted this event."),
            new("Event ID", log.EventId.ToString(), "Event IDs are meaningful together with their provider and channel."),
            new("Severity", log.Level.ToString(), "This is the event's recorded severity, not a root-cause rating.")
        };

        Add("Service", service, "Service name recorded by the event.");
        Add("Application", app, "Application identified by the event as affected.");
        Add("Faulting module", module, "Module named in the event; this does not by itself prove the module caused the fault.");
        Add("Account", user, "Account named in the event.");
        Add("Source address", address is "-" or "::1" or "127.0.0.1" ? null : address, "Network address recorded for the event; verify it against neighboring authentication events.");
        Add("Status / error code", status ?? explanation.DecodedStatusCode, explanation.StatusMeaning ?? "Code extracted from event data.");
        Add("DNS name", queryName, "Name recorded in the event's DNS fields.");

        if (log.EventId == 41 && provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
        {
            causes.Insert(0, "Windows recorded that the previous shutdown was not clean; this event alone does not identify whether power loss, a forced reset, a freeze, or a bugcheck caused it.");
            actions.Insert(0, "Compare the timestamp with BugCheck/WHEA events, dump files, and power or thermal telemetry before attributing a cause.");
        }
        else if (log.EventId == 4625)
        {
            if (!string.IsNullOrWhiteSpace(user)) actions.Insert(0, $"Review other failed and successful logons for account '{user}' in the same time window.");
            if (address is not null and not "-" and not "::1" and not "127.0.0.1")
                actions.Insert(0, $"Check whether address {address} appears in repeated failures or a successful logon before changing firewall or account settings.");
            else
                actions.Insert(0, "The source address is local or unavailable in this event; use the logon type, workstation, and neighboring records to identify the origin.");
        }
        else if (provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(service))
        {
            actions.Insert(0, $"Inspect service '{service}' state, startup configuration, dependencies, and the first related failure before restarting or reconfiguring it.");
        }
        else if (category == "Storage health")
        {
            actions.Insert(0, "Identify the affected disk or volume, secure a current backup, and run chkdsk with appropriate repair options during a maintenance window.");
        }
        else if (category == "Network connectivity" && !string.IsNullOrWhiteSpace(queryName))
        {
            actions.Insert(0, $"Check whether DNS resolution for '{queryName}' recovered and compare the selected resolver with nearby DNS or network events.");
        }

        var tags = new List<string>
        {
            Slug(category), $"severity:{Slug(log.Level.ToString())}", $"event:{log.EventId}", $"provider:{Slug(provider)}"
        };
        if (!string.IsNullOrWhiteSpace(status)) tags.Add($"code:{Slug(status)}");
        if (log.IsRealTimeEtw) tags.Add("source:live-etw");
        if (explanation.IsCuratedKnowledge) tags.Add("knowledge:curated");

        var strength = explanation.IsCuratedKnowledge ? 95 :
            !string.IsNullOrWhiteSpace(explanation.DecodedStatusCode) ? 82 :
            category != "System operations" ? 64 : 30;
        var basis = explanation.IsCuratedKnowledge
            ? "Curated provider/event rule; listed causes remain hypotheses."
            : !string.IsNullOrWhiteSpace(explanation.DecodedStatusCode)
                ? "A known status code was decoded; surrounding evidence is still needed for root cause."
                : category != "System operations"
                    ? "Provider or event-field classification; verify using the event data and neighboring records."
                    : "Generic event classification; limited scenario-specific knowledge matched.";

        return explanation with
        {
            Headline = headline,
            Category = category,
            Tags = tags.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            Evidence = evidence,
            RuleMatchStrength = strength,
            MatchBasis = basis,
            ProbableCauses = causes.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            RecommendedActions = actions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
        };

        void Add(string label, string? value, string interpretation)
        {
            if (!string.IsNullOrWhiteSpace(value) && value != "-") evidence.Add(new EvidenceObservation(label, value, interpretation));
        }
    }

    private static string ClassifyCategory(LogRecord log, string provider)
    {
        if (provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase) || provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) || provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase)) return "System stability";
        if (log.EventId == 4625 || provider.Contains("Security", StringComparison.OrdinalIgnoreCase) || provider.Contains("Defender", StringComparison.OrdinalIgnoreCase) || provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase)) return "Security and identity";
        if (provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase)) return "Service reliability";
        if (provider.Contains("Disk", StringComparison.OrdinalIgnoreCase) || provider.Contains("Ntfs", StringComparison.OrdinalIgnoreCase) || provider.Contains("Stor", StringComparison.OrdinalIgnoreCase)) return "Storage health";
        if (provider.Contains("DNS", StringComparison.OrdinalIgnoreCase) || provider.Contains("DHCP", StringComparison.OrdinalIgnoreCase) || provider.Contains("Tcpip", StringComparison.OrdinalIgnoreCase) || provider.Contains("Network", StringComparison.OrdinalIgnoreCase)) return "Network connectivity";
        if (provider.Contains("WindowsUpdate", StringComparison.OrdinalIgnoreCase) || provider.Contains("Servicing", StringComparison.OrdinalIgnoreCase) || provider.Contains("CBS", StringComparison.OrdinalIgnoreCase)) return "Windows servicing";
        if (provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase) || provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase) || log.EventId == 1000) return "Application reliability";
        if (provider.Contains("Display", StringComparison.OrdinalIgnoreCase) || provider.Contains("Driver", StringComparison.OrdinalIgnoreCase)) return "Device and driver health";
        if (provider.Contains("User Profile", StringComparison.OrdinalIgnoreCase) || provider.Contains("Winlogon", StringComparison.OrdinalIgnoreCase)) return "Sign-in and user profile";
        return "System operations";
    }

    private static string Headline(LogRecord log, string provider, string? service, string? app, string? module, string? user, string? address, string? queryName, LogExplanation explanation)
    {
        if (log.EventId == 41 && provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase)) return "Unexpected shutdown detected";
        if (log.EventId == 1001 && provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase))
            return explanation.DecodedFields.TryGetValue("Stop Error Name", out var stop) ? $"System stop error: {stop}" : "System stop error recorded";
        if (log.EventId == 1000 && (provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase) || app is not null))
            return $"Application crash{(app is null ? string.Empty : $": {app}")}{(module is null ? string.Empty : $" in {module}")}";
        if (log.EventId == 1026 && provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase)) return $".NET application terminated{(app is null ? string.Empty : $": {app}")}";
        if (log.EventId == 4625) return $"Sign-in failed{(user is null ? string.Empty : $" for {user}")}{(address is null or "-" ? string.Empty : $" from {address}")}";
        if (provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase))
            return $"Service issue{(service is null ? string.Empty : $": {service}")} (Event {log.EventId})";
        if (log.EventId == 1014 && provider.Contains("DNS", StringComparison.OrdinalIgnoreCase)) return $"DNS lookup timed out{(queryName is null ? string.Empty : $": {queryName}")}";
        if ((log.EventId is 7 or 11) && provider.Contains("Disk", StringComparison.OrdinalIgnoreCase)) return "Disk I/O error reported";
        if ((log.EventId is 55 or 98) && provider.Contains("Ntfs", StringComparison.OrdinalIgnoreCase)) return "Filesystem integrity issue reported";
        if (provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase)) return "Hardware error recorded";
        if (provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase)) return "Secure-channel negotiation failed";
        return $"{provider} reported {log.Level.ToString().ToLowerInvariant()} (Event {log.EventId})";
    }

    private static string? Value(LogRecord log, params string[] keys)
    {
        foreach (var key in keys)
            if ((log.NormalizedEventData.TryGetValue(key, out var value) || log.EventData.TryGetValue(key, out value)) && !string.IsNullOrWhiteSpace(value) && value != "-") return value.Trim();
        return null;
    }

    private static string Slug(string value) => TagPattern.Replace(value.ToLowerInvariant(), "-").Trim('-');
}
