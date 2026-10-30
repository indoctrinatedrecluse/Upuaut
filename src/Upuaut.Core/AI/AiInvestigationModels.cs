namespace Upuaut.Core.AI;

/// <summary>Subsystem domain requesting AI analysis.</summary>
public enum AiAnalysisDomain
{
    LogLab,
    Chronicles,
    Scout,
    CrashForensics,
    Weigher
}

/// <summary>Structured request for AI review with bounded tokens and domain-specific guardrails.</summary>
public sealed record AiInvestigationRequest(
    AiAnalysisDomain Domain,
    string Title,
    string UserPrompt,
    string SystemInstruction,
    string? UnitSummary = null,
    AiPromptBudget? Budget = null
);

/// <summary>Contract for AI review services with support for structured investigation requests.</summary>
public interface ILlmAssistantService
{
    Task<string> AnalyzeAsync(string selectedLogEntry, CancellationToken cancellationToken = default);
    Task<string> AnalyzeInvestigationAsync(AiInvestigationRequest request, CancellationToken cancellationToken = default);
}

