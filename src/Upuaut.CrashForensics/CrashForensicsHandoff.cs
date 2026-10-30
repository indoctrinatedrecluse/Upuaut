using Upuaut.CrashForensics.Models;

namespace Upuaut.CrashForensics;

/// <summary>One-shot in-process bridge from a selected Log Lab crash finding into Crash Forensics.</summary>
public sealed class CrashForensicsHandoff
{
    private readonly object _gate = new();
    private CrashLogContext? _pending;

    public void Set(CrashLogContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        lock (_gate) _pending = context with { Message = Clip(context.Message, 8_000), Explanation = Clip(context.Explanation, 4_000) };
    }

    public CrashLogContext? Take()
    {
        lock (_gate)
        {
            var result = _pending;
            _pending = null;
            return result;
        }
    }

    private static string Clip(string value, int maximum) => value.Length <= maximum ? value : value[..maximum] + "… [truncated]";
}
