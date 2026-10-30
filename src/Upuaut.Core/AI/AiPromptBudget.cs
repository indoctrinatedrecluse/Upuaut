namespace Upuaut.Core.AI;

/// <summary>
/// Describes how an AI prompt was assembled: its character ceiling, the characters actually
/// submitted, and which guardrails had to compact or reduce the selected unit.
/// A prompt inside its ceiling with no notes was sent verbatim.
/// </summary>
public sealed record AiPromptBudget(
    int CharacterLimit,
    int CharacterCount,
    bool WasCompacted,
    IReadOnlyList<string> AppliedGuardrails)
{
    /// <summary>Requested characters as a percentage of the hard ceiling (0-100).</summary>
    public int UtilizationPercent => CharacterLimit <= 0
        ? 0
        : Math.Clamp((int)Math.Round(CharacterCount * 100d / CharacterLimit, MidpointRounding.AwayFromZero), 0, 100);

    /// <summary>Short, user-facing description suitable for an AI review panel subtitle.</summary>
    public string Describe()
    {
        var size = $"{CharacterCount:N0} / {CharacterLimit:N0} chars";
        return WasCompacted
            ? $"{size} · context compacted ({AppliedGuardrails.Count} guardrail(s))"
            : $"{size} · full selected context";
    }

    /// <summary>One line per applied guardrail, for tooltips and diagnostics.</summary>
    public string Explain() => AppliedGuardrails.Count == 0
        ? "No guardrail compaction was required for this request."
        : string.Join(Environment.NewLine, AppliedGuardrails.Select(note => $"• {note}"));
}
