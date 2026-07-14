namespace MRTW.Core;

/// <summary>One target outcome produced by a CLI batch analysis.</summary>
public sealed record BatchAnalysisItem(
    string Target,
    string Status,
    int ExitCode,
    string? Reason,
    string? CaseOutput);

/// <summary>Stable batch completion payload used by text, JSONL, and summary files.</summary>
public sealed record BatchAnalysisSummary(
    DateTimeOffset CompletedAtUtc,
    int Succeeded,
    int Failed,
    int Skipped,
    IReadOnlyList<BatchAnalysisItem> Items)
{
    /// <summary>Partial target failures are intentionally distinguishable from command/input failures.</summary>
    public int ExitCode => Failed > 0 ? 10 : 0;
}

/// <summary>Validation rules that keep a batch target bound to its enumerated sample.</summary>
public static class BatchAnalysisPolicy
{
    public static void RejectCommandOverride(bool commandRequested)
    {
        if (commandRequested)
        {
            throw new ArgumentException("batch does not support --cmd because it can execute a command that differs from the enumerated sample and cannot be contained per sample.");
        }
    }
}
