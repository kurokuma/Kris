using System.Text.Json;

namespace MRTW.Core;

/// <summary>Conservative, bounded IOC extraction. It only reads already collected data.</summary>
public static class IocLedgerBuilder
{
    public const int MaximumEntries = 1024;
    public const int MaximumValueLength = 1024;

    public static IReadOnlyList<IocLedgerEntry> Build(StaticAnalysisResult? analysis, IReadOnlyList<TimelineEvent> events, DateTimeOffset startedAt, out long dropped)
    {
        var candidates = new List<Candidate>();
        DateTimeOffset staticTime = startedAt;
        if (analysis is not null)
        {
            Add(candidates, "imphash", analysis.Imphash, "StaticAnalysis", "", null, staticTime);
            Add(candidates, "pdb_path", analysis.PdbPath, "StaticAnalysis", "", null, staticTime);
        }
        foreach (var e in events)
        {
            DateTimeOffset time = e.CapturedAtUtc ?? startedAt.Add(e.Time);
            // Hook fields are structured JSON; do not infer host IOCs from display strings.
            if (e.Source.Equals("Hook", StringComparison.OrdinalIgnoreCase) && TryPayload(e.RawJson, out var payload))
            {
                Add(candidates, "mutex", payload.Get("mutex_name"), e.Source, e.ProcessGuid, e.Id, time);
                Add(candidates, "named_pipe", payload.Get("pipe_name"), e.Source, e.ProcessGuid, e.Id, time);
                if (e.Action.Contains("service", StringComparison.OrdinalIgnoreCase)) Add(candidates, "service", payload.Get("service_name"), e.Source, e.ProcessGuid, e.Id, time);
                if (e.Action.Contains("task", StringComparison.OrdinalIgnoreCase)) Add(candidates, "scheduled_task", payload.Get("task_name"), e.Source, e.ProcessGuid, e.Id, time);
            }
            // Snapshot Task/Service observations are explicitly host-wide: no GUID is fabricated.
            if (e.Category == EventCategory.Service) Add(candidates, "service", e.ObjectValue, e.Source, e.ProcessGuid, e.Id, time);
            if (e.Category == EventCategory.Task) Add(candidates, "scheduled_task", e.ObjectValue, e.Source, e.ProcessGuid, e.Id, time);
        }

        dropped = 0;
        var result = new List<IocLedgerEntry>();
        foreach (var group in candidates.GroupBy(c => c.Type + "\u001f" + c.Normalized, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            if (result.Count >= MaximumEntries) { dropped += group.Count(); continue; }
            var originals = group.Select(c => c.Original).Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToArray();
            var sources = group.Select(c => c.Source).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToArray();
            var processes = group.Select(c => c.ProcessGuid).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToArray();
            var evidence = group.Where(c => c.EvidenceId.HasValue).Select(c => c.EvidenceId!.Value).Distinct().OrderBy(v => v).ToArray();
            dropped += Math.Max(0, originals.Length - 32) + Math.Max(0, sources.Length - 32) + Math.Max(0, processes.Length - 64) + Math.Max(0, evidence.Length - 256);
            result.Add(new IocLedgerEntry(group.First().Type, group.First().Normalized,
                originals.Take(32).ToArray(),
                group.Min(c => c.Time), group.Max(c => c.Time),
                sources.Take(32).ToArray(), processes.Take(64).ToArray(), evidence.Take(256).ToArray()));
        }
        return result;
    }

    private static void Add(List<Candidate> values, string type, string? original, string source, string processGuid, int? evidenceId, DateTimeOffset time)
    {
        if (string.IsNullOrWhiteSpace(original) || original.Length > MaximumValueLength) return;
        string? normalized = Normalize(type, original);
        if (normalized is not null) values.Add(new(type, normalized, original, source, processGuid, evidenceId, time));
    }

    internal static string? Normalize(string type, string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Length == 0 || trimmed.Length > MaximumValueLength) return null;
        return type switch
        {
            "imphash" => trimmed.All(Uri.IsHexDigit) && trimmed.Length == 32 ? trimmed.ToLowerInvariant() : null,
            "mutex" or "named_pipe" => NormalizeNamespace(trimmed),
            "service" or "scheduled_task" => trimmed.Replace('/', '\\').Trim().ToLowerInvariant(),
            "pdb_path" => trimmed.Replace('/', '\\').Trim().ToLowerInvariant(),
            _ => null
        };
    }

    private static string NormalizeNamespace(string value)
    {
        string text = value.Replace('/', '\\').Trim();
        return text.StartsWith("local\\", StringComparison.OrdinalIgnoreCase) || text.StartsWith("global\\", StringComparison.OrdinalIgnoreCase)
            ? text[..6].ToLowerInvariant() + text[6..] : text;
    }

    private static bool TryPayload(string json, out Payload payload)
    {
        payload = default;
        try { using var doc = JsonDocument.Parse(json); payload = new(doc.RootElement.Clone()); return doc.RootElement.ValueKind == JsonValueKind.Object; }
        catch (JsonException) { return false; }
    }
    private readonly record struct Payload(JsonElement Root) { public string Get(string name) => Root.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : ""; }
    private sealed record Candidate(string Type, string Normalized, string Original, string Source, string ProcessGuid, int? EvidenceId, DateTimeOffset Time);
}
