using System.Xml.Linq;

namespace Upuaut.Chronicles.Parsers;

/// <summary>
/// High-speed XML extractor for structured EventData and UserData properties.
/// </summary>
public static class EventXmlParser
{
    public static IReadOnlyDictionary<string, string> ExtractProperties(string? rawXml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(rawXml))
        {
            return result;
        }

        try
        {
            var doc = XDocument.Parse(rawXml);
            if (doc.Root == null) return result;

            // Preserve provider field names as the raw view while flattening nested event templates.
            var eventData = doc.Root.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("EventData", StringComparison.OrdinalIgnoreCase));
            if (eventData != null)
            {
                int unnamedIndex = 1;
                foreach (var dataElement in eventData.Elements())
                {
                    var nameAttr = dataElement.Attribute("Name")?.Value;
                    var key = !string.IsNullOrWhiteSpace(nameAttr) ? nameAttr : $"Param{unnamedIndex++}";
                    Flatten(dataElement, key, result);
                }
            }

            // UserData templates often nest values several levels deep and use namespace-qualified names.
            var userData = doc.Root.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("UserData", StringComparison.OrdinalIgnoreCase));
            if (userData != null)
            {
                foreach (var child in userData.Elements()) Flatten(child, child.Name.LocalName, result);
            }

        }
        catch
        {
            // Fall back to empty dictionary if malformed XML
        }

        return result;
    }

    public static IReadOnlyDictionary<string, string> NormalizeProperties(IReadOnlyDictionary<string, string> properties)
    {
        var normalized = new Dictionary<string, string>(properties, StringComparer.OrdinalIgnoreCase);
        AddAliases(normalized);
        return normalized;
    }

    private static void Flatten(System.Xml.Linq.XElement element, string path, IDictionary<string, string> output)
    {
        var children = element.Elements().ToList();
        if (children.Count == 0)
        {
            var value = element.Value.Trim();
            if (value.Length == 0) return;
            var key = path;
            for (var suffix = 2; output.ContainsKey(key); suffix++) key = $"{path}#{suffix}";
            output[key] = value;
            return;
        }

        foreach (var child in children)
        {
            var named = child.Attribute("Name")?.Value;
            var childName = !string.IsNullOrWhiteSpace(named) ? named : child.Name.LocalName;
            Flatten(child, $"{path}.{childName}", output);
        }
    }

    private static void AddAliases(IDictionary<string, string> fields)
    {
        var aliases = new (string Source, string Target)[]
        {
            ("FaultingApplicationName", "ApplicationName"), ("FaultingApplicationPath", "ApplicationPath"),
            ("FaultingModuleName", "ModuleName"), ("ExceptionCode", "StatusCode"),
            ("IpAddress", "SourceIpAddress"), ("IpPort", "SourcePort"),
            ("TargetUserName", "AccountName"), ("TargetDomainName", "DomainName"),
            ("WorkstationName", "SourceWorkstation"), ("QueryName", "DnsQueryName")
        };
        foreach (var (source, target) in aliases)
            if (!fields.ContainsKey(target) && fields.TryGetValue(source, out var value) && !string.IsNullOrWhiteSpace(value)) fields[target] = value;
    }
}
