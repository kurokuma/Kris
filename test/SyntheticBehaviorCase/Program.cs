using System.Text.Json;
using MRTW.Core;

string outputRoot = args.Length > 0 ? args[0] : Path.Combine(AppContext.BaseDirectory, "synthetic-case");
Directory.CreateDirectory(outputRoot);

var started = DateTimeOffset.Now;
var events = new List<TimelineEvent>();
int id = 1;
string caseId = "case-synthetic-" + Guid.NewGuid().ToString("N");
string processGuid = $"{caseId}:4242:{started.UtcTicks}";

events.Add(E(id++, 0.10, "synthetic-sample.exe", 4242, EventCategory.Process, "Process Start", "synthetic-sample.exe", "Synthetic process start", EventSeverity.Informational, "Synthetic", processGuid));
events.Add(E(id++, 0.30, "synthetic-sample.exe", 4242, EventCategory.Api, "VirtualAllocEx", "pid-5000", "Synthetic remote allocation event", EventSeverity.High, "Synthetic", processGuid, "T1055", "Process Injection", "High"));
events.Add(E(id++, 0.40, "synthetic-sample.exe", 4242, EventCategory.Api, "WriteProcessMemory", "pid-5000", "Synthetic remote memory write event", EventSeverity.High, "Synthetic", processGuid, "T1055", "Process Injection", "High"));
events.Add(E(id++, 0.50, "synthetic-sample.exe", 4242, EventCategory.Api, "CreateRemoteThread", "pid-5000", "Synthetic remote execution event", EventSeverity.High, "Synthetic", processGuid, "T1055", "Process Injection", "High"));
events.Add(E(id++, 1.00, "synthetic-sample.exe", 4242, EventCategory.File, "CreateFileW", @"C:\Temp\sample.doc.locked", "Synthetic file create", EventSeverity.Medium, "Synthetic", processGuid));
events.Add(E(id++, 1.10, "synthetic-sample.exe", 4242, EventCategory.File, "WriteFile", @"C:\Temp\sample.doc.locked", "Synthetic file write", EventSeverity.Medium, "Synthetic", processGuid));
events.Add(E(id++, 1.20, "synthetic-sample.exe", 4242, EventCategory.Api, "CryptEncrypt", "buffer", "Synthetic crypto API event", EventSeverity.Medium, "Synthetic", processGuid, "T1486", "Data Encrypted for Impact", "Low"));
events.Add(E(id++, 1.40, "synthetic-sample.exe", 4242, EventCategory.Registry, "RegSetValueExW", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Synthetic", "Synthetic persistence registry event", EventSeverity.High, "Synthetic", processGuid, "T1547", "Boot or Logon Autostart Execution", "Medium"));
events.Add(E(id++, 1.60, "synthetic-sample.exe", 4242, EventCategory.Api, "AmsiScanBuffer", "synthetic-script", "Synthetic AMSI event", EventSeverity.Medium, "Synthetic", processGuid, "T1562.001", "Disable or Modify Tools", "Medium"));
events.Add(E(id++, 1.70, "synthetic-sample.exe", 4242, EventCategory.Api, "VirtualProtect", "memory page", "Synthetic executable memory permission event", EventSeverity.Medium, "Synthetic", processGuid, "T1562.001", "Disable or Modify Tools", "Medium"));
events.Add(E(id++, 2.00, "synthetic-sample.exe", 4242, EventCategory.Process, "Process Exit", "synthetic-sample.exe", "Synthetic process exit", EventSeverity.Informational, "Synthetic", processGuid));

var correlated = BehaviorCorrelator.Correlate(events).ToArray();
var data = new CaseData(
    caseId,
    "synthetic_behavior_case",
    "synthetic-sample.exe",
    "synthetic://no-executable",
    "synthetic",
    started,
    TimeSpan.FromSeconds(2),
    null,
    new[]
    {
        new ProcessNode("synthetic-sample.exe", 4242, null, processGuid, "synthetic-sample.exe", "synthetic://no-executable", started, started.AddSeconds(2), correlated.Length, 0, 2, 1)
    },
    correlated,
    BuildArtifacts(correlated, started),
    Array.Empty<NetworkSession>(),
    "Synthetic case only. No operating-system behaviors were executed.");

File.WriteAllText(Path.Combine(outputRoot, "case.json"), JsonSerializer.Serialize(data, JsonDefaults.Options));
Console.WriteLine(Path.Combine(outputRoot, "case.json"));

static TimelineEvent E(int id, double seconds, string process, int pid, EventCategory category, string action, string obj, string summary, EventSeverity severity, string source, string processGuid, string techniqueId = "", string techniqueName = "", string confidence = "")
{
    var raw = JsonSerializer.Serialize(new
    {
        source,
        synthetic = true,
        category = category.ToString(),
        action,
        pid,
        obj,
        summary,
        technique_id = techniqueId,
        technique_name = techniqueName,
        confidence
    }, JsonDefaults.Options);

    return new TimelineEvent(id, TimeSpan.FromSeconds(seconds), process, pid, category, action, obj, summary, severity, source, raw, techniqueId, techniqueName, confidence, processGuid);
}

static IReadOnlyList<ArtifactItem> BuildArtifacts(IReadOnlyList<TimelineEvent> events, DateTimeOffset started)
{
    return events
        .Where(e => e.Category is EventCategory.File or EventCategory.Registry or EventCategory.Api or EventCategory.Behavior)
        .GroupBy(e => e.Category)
        .Select(g => new ArtifactItem(
            g.Key.ToString(),
            string.Join(", ", g.Select(e => e.ObjectValue).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
            started.Add(g.Min(e => e.Time)),
            started.Add(g.Max(e => e.Time)),
            g.Count(),
            "synthetic-sample.exe",
            g.Any(e => e.Severity is EventSeverity.Critical or EventSeverity.High) ? EventSeverity.High : EventSeverity.Medium))
        .OrderByDescending(a => a.EventCount)
        .ToArray();
}
