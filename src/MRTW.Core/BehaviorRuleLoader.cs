using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MRTW.Core;

public sealed record BehaviorRule(string Action, string Summary, EventSeverity Severity, string TechniqueId,
    string TechniqueName, string Confidence, IReadOnlyList<string> Actions, bool RequireAll = true,
    int MinimumMatches = 1, string Version = "1", string Tactic = "", int TimeWindowSeconds = 300,
    bool RequireOrder = false, IReadOnlyList<string>? ExcludeActions = null, string RuleHash = "");

internal static class BehaviorRuleLoader
{
    private const int MaxFileBytes = 1024 * 1024;
    private const int MaxRules = 64;
    public static IReadOnlyList<BehaviorRule> Load() => Read(Environment.GetEnvironmentVariable("MRTW_BEHAVIOR_RULES"));
    internal static IReadOnlyList<BehaviorRule> LoadFileForTest(string path) => Read(path);

    private static IReadOnlyList<BehaviorRule> Read(string? configured)
    {
        string path = string.IsNullOrWhiteSpace(configured) ? Path.Combine(AppContext.BaseDirectory, "rules", "behavior-rules.json") : configured;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length is <= 1 or > MaxFileBytes) return Fallback;
            byte[] bytes = File.ReadAllBytes(path);
            var options = new JsonSerializerOptions(JsonDefaults.Options) { MaxDepth = 16 };
            var parsed = JsonSerializer.Deserialize<BehaviorRule[]>(bytes, options);
            if (parsed is null || parsed.Length is 0 or > MaxRules) return Fallback;
            var valid = parsed.Where(IsValid).Select(r => r with { RuleHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(r, JsonDefaults.Options)))).ToLowerInvariant() }).ToArray();
            return valid.Length == parsed.Length ? valid : Fallback;
        }
        catch { return Fallback; }
    }

    private static bool IsValid(BehaviorRule r) =>
        !string.IsNullOrWhiteSpace(r.Action) && r.Action.Length <= 160 &&
        !string.IsNullOrWhiteSpace(r.Summary) && r.Summary.Length <= 2000 &&
        !string.IsNullOrWhiteSpace(r.TechniqueId) && r.TechniqueId.Length <= 32 &&
        !string.IsNullOrWhiteSpace(r.TechniqueName) && r.TechniqueName.Length <= 160 &&
        !string.IsNullOrWhiteSpace(r.Version) && r.Version.Length <= 40 &&
        r.Actions is { Count: > 0 and <= 64 } && r.Actions.All(a => !string.IsNullOrWhiteSpace(a) && a.Length <= 160) &&
        r.MinimumMatches is >= 1 and <= 64 && r.TimeWindowSeconds is >= 1 and <= 86400 &&
        (r.ExcludeActions?.Count ?? 0) <= 64;

    private static BehaviorRule[] Fallback =>
    [new("Remote Thread Injection", "External rule: remote allocation, write, and thread creation were observed.", EventSeverity.High, "T1055", "Process Injection", "High", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], Version: "builtin-1", Tactic: "Defense Evasion", RequireOrder: true)];
}
