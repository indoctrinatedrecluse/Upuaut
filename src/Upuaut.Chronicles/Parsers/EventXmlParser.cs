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

            // 1. Check <EventData>
            var eventData = doc.Root.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("EventData", StringComparison.OrdinalIgnoreCase));
            if (eventData != null)
            {
                int unnamedIndex = 1;
                foreach (var dataElement in eventData.Elements())
                {
                    var nameAttr = dataElement.Attribute("Name")?.Value;
                    var key = !string.IsNullOrWhiteSpace(nameAttr) ? nameAttr : $"Param{unnamedIndex++}";
                    result[key] = dataElement.Value;
                }
            }

            // 2. Check <UserData>
            var userData = doc.Root.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("UserData", StringComparison.OrdinalIgnoreCase));
            if (userData != null)
            {
                foreach (var child in userData.Elements())
                {
                    foreach (var prop in child.Elements())
                    {
                        result[prop.Name.LocalName] = prop.Value;
                    }
                }
            }
        }
        catch
        {
            // Fall back to empty dictionary if malformed XML
        }

        return result;
    }
}
