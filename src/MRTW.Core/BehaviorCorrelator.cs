using System.Text.Json;
using System.Text.Json.Nodes;

namespace MRTW.Core;

public static class BehaviorCorrelator
{
    public static IReadOnlyList<TimelineEvent> Correlate(IReadOnlyList<TimelineEvent> events, CommandNormalizationBudget? commandBudget = null)
    {
        if (events.Count == 0)
        {
            return events;
        }

        var output = events.OrderBy(e => e.Time).ToList();
        commandBudget ??= new CommandNormalizationBudget();
        int nextId = output.Count == 0 ? 1 : output.Max(e => e.Id) + 1;
        // Configurable rules are untrusted input.  Keep their total work bounded across
        // all process groups; built-in correlations below remain complete.
        var ruleBudget = new RuleEvaluationBudget();
        var configuredRules = BehaviorRuleLoader.Load();
        foreach (var group in output.Where(e => e.Category != EventCategory.Behavior).GroupBy(e => e.Pid))
        {
            AddProcessInjection(output, group.ToArray(), ref nextId);
            AddProcessHollowing(output, group.ToArray(), ref nextId);
            AddRansomwareLikeFileEncryption(output, group.ToArray(), ref nextId);
            AddPersistence(output, group.ToArray(), ref nextId);
            AddCredentialAccess(output, group.ToArray(), ref nextId);
            AddDnsC2LikeActivity(output, group.ToArray(), ref nextId);
            AddScriptExecution(output, group.ToArray(), ref nextId);
            AddAntiAnalysis(output, group.ToArray(), ref nextId);
            AddSuspiciousModuleLoad(output, group.ToArray(), ref nextId);
            AddDiscoveryActivity(output, group.ToArray(), ref nextId);
            AddTokenManipulation(output, group.ToArray(), ref nextId);
            AddStealerBehavior(output, group.ToArray(), ref nextId);
            AddLolbinExecution(output, group.ToArray(), ref nextId);
            AddEncodedCommand(output, group.ToArray(), ref nextId, commandBudget);
            AddAmsiEtwTamper(output, group.ToArray(), ref nextId);
            AddIpcActivity(output, group.ToArray(), ref nextId);
            AddComWmiActivity(output, group.ToArray(), ref nextId);
            AddServiceDriverActivity(output, group.ToArray(), ref nextId);
            AddNetworkConfigurationActivity(output, group.ToArray(), ref nextId);
            AddExceptionBasedEvasion(output, group.ToArray(), ref nextId);
            AddSystemEnvironmentProfiling(output, group.ToArray(), ref nextId);
            AddConfiguredRules(output, group.ToArray(), ref nextId, ruleBudget, configuredRules);
        }

        var ordered = output.OrderBy(e => e.Time).ToArray();
        var idMap = ordered
            .Select((timelineEvent, index) => (timelineEvent.Id, NewId: index + 1))
            .GroupBy(value => value.Id)
            .ToDictionary(group => group.Key, group => group.First().NewId);
        return ordered.Select((timelineEvent, index) => timelineEvent with
        {
            Id = index + 1,
            RawJson = timelineEvent.Category == EventCategory.Behavior
                ? RewriteEvidenceEventIds(timelineEvent.RawJson, idMap)
                : timelineEvent.RawJson
        }).ToArray();
    }

    private static void AddEncodedCommand(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId, CommandNormalizationBudget budget)
    {
        foreach (var e in events)
        {
            var command = CommandNormalizationService.Normalize(e.ObjectValue, budget).Concat(CommandNormalizationService.Normalize(e.Summary, budget)).FirstOrDefault(c => c.Status == "decoded");
            if (command is null) continue;
            string raw = JsonSerializer.Serialize(new { finding = "encoded_command_decoded", evidence_event_ids = new[] { e.Id }, decoder = command.Decoder, status = command.Status, lolbin = command.LolBin });
            output.Add(new TimelineEvent(nextId++, e.Time, e.Process, e.Pid, EventCategory.Behavior, "Encoded Command Decoded", command.Normalized, "Bounded Base64 text decoding evidence; content was not executed.", EventSeverity.Medium, "Behavior", raw, "T1140", "Deobfuscate/Decode Files or Information", "Medium", e.ProcessGuid, e.CapturedAtUtc));
            break;
        }
    }

    private static string RewriteEvidenceEventIds(string rawJson, IReadOnlyDictionary<int, int> idMap)
    {
        try
        {
            if (JsonNode.Parse(rawJson) is not JsonObject document || document["evidence_event_ids"] is not JsonArray evidenceIds)
                return rawJson;

            var rewritten = new JsonArray();
            foreach (var value in evidenceIds)
            {
                if (value is JsonValue jsonValue)
                {
                    try
                    {
                        int oldId = jsonValue.GetValue<int>();
                        if (idMap.TryGetValue(oldId, out int newId))
                        {
                            rewritten.Add(newId);
                            continue;
                        }
                    }
                    catch (InvalidOperationException)
                    {
                        // Preserve malformed or non-integer evidence values verbatim.
                    }
                }
                rewritten.Add(value?.DeepClone());
            }
            document["evidence_event_ids"] = rewritten;
            return document.ToJsonString(JsonDefaults.Options);
        }
        catch (JsonException)
        {
            return rawJson;
        }
    }

    private static void AddConfiguredRules(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId, RuleEvaluationBudget budget, IReadOnlyList<BehaviorRule> rules)
    {
        const int MaxEventsPerGroup = 20_000;
        const int MaxOrderedChecksPerRule = 2_048;
        var orderedGroup = events.OrderBy(e => e.Time).ThenBy(e => e.Id).Take(MaxEventsPerGroup).ToArray();
        foreach (var rule in rules)
        {
            // Each rule needs one pass over the group.  Do not begin a partial rule
            // evaluation once the case-level budget is exhausted.
            if (!budget.TryConsumeEventChecks(orderedGroup.Length)) return;
            var actionSet = rule.Actions.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var excludeSet = (rule.ExcludeActions ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int[]? nextExclude = null;
            if (excludeSet.Count > 0)
            {
                nextExclude = new int[orderedGroup.Length]; int next = -1;
                for (int i = orderedGroup.Length - 1; i >= 0; i--) { if (excludeSet.Contains(orderedGroup[i].Action)) next = i; nextExclude[i] = next; }
            }
            int left = 0, excludes = 0, orderedChecks = 0, totalMatches = 0;
            for (int right = 0; right < orderedGroup.Length; right++)
            {
                var added = orderedGroup[right]; if (actionSet.Contains(added.Action)) { counts[added.Action] = counts.GetValueOrDefault(added.Action) + 1; totalMatches++; } if (excludeSet.Contains(added.Action)) excludes++;
                while (orderedGroup[right].Time - orderedGroup[left].Time > TimeSpan.FromSeconds(rule.TimeWindowSeconds))
                {
                    var removed = orderedGroup[left++]; if (actionSet.Contains(removed.Action)) { if (--counts[removed.Action] == 0) counts.Remove(removed.Action); totalMatches--; } if (excludeSet.Contains(removed.Action)) excludes--;
                }
                bool applies = excludes == 0 && (rule.RequireAll ? rule.Actions.All(counts.ContainsKey) : totalMatches >= Math.Max(1, rule.MinimumMatches));
                if (applies && nextExclude is not null && nextExclude[left] >= 0 && orderedGroup[nextExclude[left]].Time <= orderedGroup[left].Time.Add(TimeSpan.FromSeconds(rule.TimeWindowSeconds))) applies = false;
                if (applies && rule.RequireOrder)
                {
                    if (++orderedChecks > MaxOrderedChecksPerRule || !budget.TryConsumeOrderedComparisons(right - left + 1)) break;
                    int cursor = 0; for (int i = left; i <= right; i++) if (cursor < rule.Actions.Count && orderedGroup[i].Action.Equals(rule.Actions[cursor], StringComparison.OrdinalIgnoreCase)) cursor++;
                    applies = cursor == rule.Actions.Count;
                }
                if (applies) { var evidence = orderedGroup[left..(right + 1)].Where(e => actionSet.Contains(e.Action)).ToArray(); AddBehavior(output, evidence, ref nextId, rule.Action, $"{rule.Summary} [rule_version={rule.Version}; tactic={rule.Tactic}; rule_hash={rule.RuleHash}]", rule.Severity, rule.TechniqueId, rule.TechniqueName, rule.Confidence); break; }
            }
        }
    }

    private sealed class RuleEvaluationBudget
    {
        private const long MaxEventChecks = 1_500_000;
        private const long MaxOrderedComparisons = 1_000_000;
        private long _remainingEventChecks = MaxEventChecks;
        private long _remainingOrderedComparisons = MaxOrderedComparisons;

        public bool TryConsumeEventChecks(int count) => TryConsume(ref _remainingEventChecks, count);
        public bool TryConsumeOrderedComparisons(int count) => TryConsume(ref _remainingOrderedComparisons, count);

        private static bool TryConsume(ref long remaining, int count)
        {
            if (count < 0 || remaining < count) return false;
            remaining -= count;
            return true;
        }
    }

    private static void AddProcessInjection(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        string[] alloc = ["VirtualAllocEx", "VirtualProtectEx"];
        string[] write = ["WriteProcessMemory"];
        string[] execute = ["CreateRemoteThread", "QueueUserAPC"];
        if (HasAny(events, alloc) && HasAny(events, write) && HasAny(events, execute))
        {
            AddBehavior(output, events, ref nextId, "Process Injection Detected", "Remote memory allocation, process-memory write, and remote execution APIs were observed in sequence.", EventSeverity.High, "T1055", "Process Injection", "High");
        }
    }

    private static void AddProcessHollowing(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        bool suspendedChild = events.Any(e => e.Action is "CreateProcessW" or "CreateProcessA" && JsonNumber(e.RawJson, "creation_flags") is uint flags && (flags & 0x4) != 0);
        bool contextSwap = HasAny(events, ["WriteProcessMemory"]) && HasAny(events, ["SetThreadContext"]) && HasAny(events, ["ResumeThread"]);
        if (suspendedChild && contextSwap)
        {
            AddBehavior(output, events, ref nextId, "Possible Process Hollowing", "A suspended process was created and then memory/context manipulation APIs were observed.", EventSeverity.High, "T1055.012", "Process Hollowing", "Medium");
        }
    }

    private static void AddRansomwareLikeFileEncryption(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        int writes = events.Count(e => e.Action == "WriteFile");
        int creates = events.Count(e => e.Action == "CreateFileW");
        int renames = events.Count(e => e.Action is "MoveFileExW" or "SetFileInformationByHandle");
        int deletes = events.Count(e => e.Action == "DeleteFileW");
        int crypto = events.Count(e => e.Action is "CryptEncrypt" or "BCryptEncrypt" or "BCryptGenerateSymmetricKey" or "CryptGenRandom");
        bool backupTamper = events.Any(e => ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "vssadmin", "wmic shadowcopy", "wbadmin", "bcdedit", "reagentc"));
        bool manyFileOps = writes >= 25 && creates >= 15;
        bool rewriteAndRename = writes >= 10 && renames >= 5;
        bool destructive = writes >= 10 && deletes >= 5;
        bool cryptoAndWrites = crypto >= 3 && writes >= 5;
        if (manyFileOps || rewriteAndRename || destructive || cryptoAndWrites || backupTamper)
        {
            AddBehavior(output, events, ref nextId, "Ransomware-like Impact", $"Ransomware-style impact pattern observed: writes={writes}, creates={creates}, renames={renames}, deletes={deletes}, crypto={crypto}, backup_tamper={backupTamper}.", EventSeverity.High, "T1486", "Data Encrypted for Impact", "Medium");
        }
    }

    private static void AddPersistence(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var persistenceEvents = events.Where(e =>
            e.Action is "CreateServiceW" or "ChangeServiceConfigW" ||
            e.Action is "Persistence Created" or "Persistence Modified" ||
            (e.Action is "RegSetValueExW" or "RegSetKeyValueW" or "RegCreateKeyExW" &&
            ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "Run", "RunOnce", "Services", "Winlogon", "AppInit_DLLs", "Image File Execution Options", "Active Setup"))).ToArray();
        if (persistenceEvents.Length > 0)
        {
            AddBehavior(output, persistenceEvents, ref nextId, "Persistence Established", "A read-only snapshot diff or runtime event identified an autostart persistence change.", EventSeverity.High, "T1547", "Boot or Logon Autostart Execution", "Medium");
        }
    }

    private static void AddCredentialAccess(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var credentialEvents = events.Where(e => e.Category == EventCategory.Credential || e.Action is "CryptUnprotectData" or "CredReadW" or "MiniDumpWriteDump").ToArray();
        if (credentialEvents.Length > 0)
        {
            string action = credentialEvents.Any(e => e.Action == "MiniDumpWriteDump") ? "LSASS Dump Attempt" : "Credential Access Attempt";
            string id = credentialEvents.Any(e => e.Action == "MiniDumpWriteDump") ? "T1003.001" : "T1003";
            string name = credentialEvents.Any(e => e.Action == "MiniDumpWriteDump") ? "LSASS Memory" : "OS Credential Dumping";
            AddBehavior(output, credentialEvents, ref nextId, action, "Credential access APIs or dump creation APIs were observed.", EventSeverity.High, id, name, "High");
        }
    }

    private static void AddDnsC2LikeActivity(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var dnsEvents = events.Where(e => e.Category == EventCategory.Dns).ToArray();
        bool manyQueries = dnsEvents.Length >= 10;
        bool longQuery = dnsEvents.Any(e => (e.ObjectValue.Length >= 50 || e.Summary.Length >= 80));
        if (manyQueries || longQuery)
        {
            AddBehavior(output, dnsEvents, ref nextId, "DNS C2-like Activity", $"DNS activity pattern observed: queries={dnsEvents.Length}, long_query={longQuery}.", EventSeverity.Medium, "T1071.004", "DNS", "Medium");
        }
    }

    private static void AddScriptExecution(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var scriptEvents = events.Where(e => (e.Action is "CreateProcessW" or "CreateProcessA" or "ShellExecuteW" or "ShellExecuteA" or "ShellExecuteExW") &&
            ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil")).ToArray();
        if (scriptEvents.Length > 0)
        {
            AddBehavior(output, scriptEvents, ref nextId, "Script Execution", "A command or scripting interpreter was launched by the sample process tree.", EventSeverity.Medium, "T1059", "Command and Scripting Interpreter", "Medium");
        }
    }

    private static void AddSuspiciousModuleLoad(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var moduleEvents = events.Where(e => (e.Action is "LoadLibraryW" or "LoadLibraryExW" or "LdrLoadDll") &&
            (ContainsAny(e.ObjectValue + " " + e.RawJson, "\\temp\\", "\\appdata\\", "\\programdata\\", "\\downloads\\") || LooksRelativeDll(e.ObjectValue))).ToArray();
        if (moduleEvents.Length > 0)
        {
            AddBehavior(output, moduleEvents, ref nextId, "Suspicious DLL Load", "A DLL was loaded from a user-writable or relative location often used for sideloading.", EventSeverity.Medium, "T1574.002", "DLL Side-Loading", "Medium");
        }
    }

    private static void AddDiscoveryActivity(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        int processDiscovery = events.Count(e => e.Action is "CreateToolhelp32Snapshot" or "Process32FirstW" or "Process32NextW" or "EnumProcesses");
        int fileDiscovery = events.Count(e => e.Action is "FindFirstFileW" or "FindNextFileW");
        int registryDiscovery = events.Count(e => e.Action is "RegEnumKeyExW" or "RegEnumValueW");
        if (processDiscovery >= 3 || fileDiscovery >= 10 || registryDiscovery >= 5 || processDiscovery + fileDiscovery + registryDiscovery >= 12)
        {
            var evidence = events.Where(e => e.Action is "CreateToolhelp32Snapshot" or "Process32FirstW" or "Process32NextW" or "EnumProcesses" or "FindFirstFileW" or "FindNextFileW" or "RegEnumKeyExW" or "RegEnumValueW").ToArray();
            AddBehavior(output, evidence, ref nextId, "Discovery Activity", $"Discovery APIs were observed: process={processDiscovery}, file={fileDiscovery}, registry={registryDiscovery}.", EventSeverity.Medium, "T1082", "System Information Discovery", "Medium");
        }
    }

    private static void AddTokenManipulation(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var tokenEvents = events.Where(e => e.Action is "OpenProcessToken" or "AdjustTokenPrivileges" or "DuplicateTokenEx" or "ImpersonateLoggedOnUser" or "ShellExecuteW" or "ShellExecuteA" or "ShellExecuteExW").ToArray();
        bool strongSignal = tokenEvents.Any(e => e.Action is "AdjustTokenPrivileges" or "DuplicateTokenEx" or "ImpersonateLoggedOnUser") ||
            tokenEvents.Any(e => (e.Action is "ShellExecuteW" or "ShellExecuteA" or "ShellExecuteExW") && ContainsAny(e.RawJson, "runas"));
        if (strongSignal)
        {
            AddBehavior(output, tokenEvents, ref nextId, "Token Privilege Manipulation", "Token privilege, duplication, impersonation, or elevation-related APIs were observed.", EventSeverity.High, "T1134", "Access Token Manipulation", "High");
        }
    }

    private static void AddStealerBehavior(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var stealerEvents = events.Where(e =>
            e.Action is "OpenClipboard" or "GetClipboardData" or "SetClipboardData" or "BitBlt" or "GetDC" or "CreateCompatibleBitmap" or "GetAsyncKeyState" or "GetKeyState" or "SetWindowsHookExW" ||
            ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "\\google\\chrome\\user data", "\\microsoft\\edge\\user data", "\\mozilla\\firefox\\profiles", "\\brave-browser\\user data", "\\opera software\\", "login data", "cookies", "local state", "wallet", "metamask", "exodus", "electrum")).ToArray();
        if (stealerEvents.Length > 0)
        {
            string techniqueId = stealerEvents.Any(e => e.Action is "BitBlt" or "GetDC" or "CreateCompatibleBitmap") ? "T1113" :
                stealerEvents.Any(e => e.Action is "OpenClipboard" or "GetClipboardData" or "SetClipboardData") ? "T1115" :
                stealerEvents.Any(e => e.Action is "GetAsyncKeyState" or "GetKeyState" or "SetWindowsHookExW") ? "T1056.001" : "T1555.003";
            string techniqueName = techniqueId switch
            {
                "T1113" => "Screen Capture",
                "T1115" => "Clipboard Data",
                "T1056.001" => "Keylogging",
                _ => "Credentials from Web Browsers"
            };
            AddBehavior(output, stealerEvents, ref nextId, "Stealer-like Collection", "Clipboard, screen, keyboard, browser profile, or wallet-related access was observed.", EventSeverity.High, techniqueId, techniqueName, "Medium");
        }
    }

    private static void AddLolbinExecution(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var lolbinEvents = events.Where(e => (e.Action is "CreateProcessW" or "CreateProcessA" or "ShellExecuteW" or "ShellExecuteA" or "ShellExecuteExW") &&
            ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "msiexec", "installutil", "wmic", "schtasks", "vssadmin", "bcdedit", "curl", "wget", "powershell", "pwsh", "cmd.exe", "wscript", "cscript")).ToArray();
        if (lolbinEvents.Length > 0)
        {
            AddBehavior(output, lolbinEvents, ref nextId, "LOLBin Execution", "A Windows living-off-the-land binary or scripting interpreter was launched with arguments visible in the event details.", EventSeverity.Medium, "T1218", "System Binary Proxy Execution", "Medium");
        }
    }

    private static void AddAmsiEtwTamper(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var tamperEvents = events.Where(e => e.Action is "AmsiScanBuffer" or "EtwEventWrite" or "VirtualProtect").ToArray();
        bool strong = tamperEvents.Any(e => e.Action is "AmsiScanBuffer" or "EtwEventWrite") &&
            tamperEvents.Any(e => e.Action == "VirtualProtect" && ContainsAny(e.RawJson, "\"new_protect\":64", "\"new_protect\":128", "\"new_protect\":32"));
        if (strong || tamperEvents.Count(e => e.Action == "VirtualProtect") >= 3)
        {
            AddBehavior(output, tamperEvents, ref nextId, "AMSI/ETW Tamper Signal", "AMSI, ETW, or executable memory protection changes were observed.", EventSeverity.High, "T1562.001", "Disable or Modify Tools", "Medium");
        }
    }

    private static void AddIpcActivity(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var ipcEvents = events.Where(e => e.Action is "CreateMutexW" or "OpenMutexW" or "CreateNamedPipeW" or "ConnectNamedPipe" or "CallNamedPipeW" or "CreateFileMappingW" or "MapViewOfFile").ToArray();
        if (ipcEvents.Length >= 2 || ipcEvents.Any(e => e.Action is "CreateNamedPipeW" or "CallNamedPipeW"))
        {
            AddBehavior(output, ipcEvents, ref nextId, "IPC or Singleton Coordination", "Mutex, named pipe, or shared-memory APIs were observed.", EventSeverity.Low, "T1559", "Inter-Process Communication", "Low");
        }
    }

    private static void AddAntiAnalysis(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        string[] antiActions = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "Sleep", "SleepEx", "GetTickCount", "QueryPerformanceCounter", "GetSystemFirmwareTable"];
        var antiEvents = events.Where(e => antiActions.Contains(e.Action, StringComparer.OrdinalIgnoreCase)).ToArray();
        bool longSleep = antiEvents.Any(e => e.Action is "Sleep" or "SleepEx" && JsonNumber(e.RawJson, "milliseconds") >= 60000);
        if (antiEvents.Length >= 2 || longSleep)
        {
            AddBehavior(output, antiEvents, ref nextId, "Anti-analysis Behavior", $"Anti-analysis or timing APIs were observed: count={antiEvents.Length}, long_sleep={longSleep}.", EventSeverity.Medium, "T1497", "Virtualization/Sandbox Evasion", "Medium");
        }
    }

    private static void AddComWmiActivity(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var comEvents = events.Where(e => e.Action is "CoCreateInstance" or "CoCreateInstanceEx" or "CoGetClassObject" or "CLSIDFromProgID" or "CLSIDFromString").ToArray();
        if (comEvents.Length == 0)
        {
            return;
        }

        bool wmi = comEvents.Any(e => ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "WbemScripting", "SWbemLocator", "{4590F811-1D3A-11D0-891F-00AA004B2E24}", "{76A64158-CB41-11D1-8B02-00600806D9B6}", "winmgmts"));
        AddBehavior(output, comEvents, ref nextId, wmi ? "WMI Automation Activity" : "COM Automation Activity", wmi ? "WMI-related COM activation was observed." : "COM object activation was observed.", wmi ? EventSeverity.High : EventSeverity.Medium, wmi ? "T1047" : "T1559.001", wmi ? "Windows Management Instrumentation" : "Component Object Model", wmi ? "High" : "Medium");
    }

    private static void AddServiceDriverActivity(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var serviceEvents = events.Where(e => e.Action is "OpenSCManagerW" or "OpenServiceW" or "StartServiceW" or "ControlService" or "DeleteService" or "EnumServicesStatusExW" or "NtLoadDriver").ToArray();
        if (serviceEvents.Length == 0)
        {
            return;
        }

        if (serviceEvents.Any(e => e.Action == "NtLoadDriver"))
        {
            AddBehavior(output, serviceEvents, ref nextId, "Driver Load Attempt", "Kernel driver loading API was observed.", EventSeverity.High, "T1547.006", "Kernel Modules and Extensions", "High");
            return;
        }

        bool modifying = serviceEvents.Any(e => e.Action is "StartServiceW" or "ControlService" or "DeleteService");
        AddBehavior(output, serviceEvents, ref nextId, modifying ? "Service Control Activity" : "Service Discovery Activity", modifying ? "Service start, stop, control, or deletion APIs were observed." : "Service manager or service enumeration APIs were observed.", modifying ? EventSeverity.High : EventSeverity.Medium, modifying ? "T1569.002" : "T1007", modifying ? "Service Execution" : "System Service Discovery", modifying ? "High" : "Medium");
    }

    private static void AddNetworkConfigurationActivity(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var configEvents = events.Where(e => e.Action is "InternetSetOptionW" or "WinHttpSetOption").ToArray();
        if (configEvents.Length > 0)
        {
            AddBehavior(output, configEvents, ref nextId, "Network Configuration Change", "WinINet or WinHTTP option changes were observed, which can indicate proxy, TLS, or request-behavior manipulation.", EventSeverity.Medium, "T1090", "Proxy", "Medium");
        }
    }

    private static void AddExceptionBasedEvasion(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var evasionEvents = events.Where(e => e.Action is "SetUnhandledExceptionFilter" or "AddVectoredExceptionHandler" or "AddVectoredContinueHandler" or "OutputDebugStringW" or "GetThreadContext").ToArray();
        if (evasionEvents.Length >= 1)
        {
            AddBehavior(output, evasionEvents, ref nextId, "Exception or Debugger Evasion", "Exception-handler, debug-output, or thread-context APIs were observed.", EventSeverity.Medium, "T1622", "Debugger Evasion", "Medium");
        }
    }

    private static void AddSystemEnvironmentProfiling(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> events, ref int nextId)
    {
        var profileEvents = events.Where(e => e.Action is "GetAdaptersAddresses" or "GetComputerNameW" or "GetUserNameW" or "GetSystemFirmwareTable").ToArray();
        if (profileEvents.Length >= 2)
        {
            bool firmware = profileEvents.Any(e => e.Action == "GetSystemFirmwareTable");
            AddBehavior(output, profileEvents, ref nextId, firmware ? "Sandbox Environment Profiling" : "Host Environment Profiling", firmware ? "Firmware or host identity APIs were observed, which can be used to identify virtualized sandboxes." : "Host identity or network adapter profiling APIs were observed.", EventSeverity.Medium, firmware ? "T1497" : "T1082", firmware ? "Virtualization/Sandbox Evasion" : "System Information Discovery", "Medium");
        }
    }

    private static void AddBehavior(List<TimelineEvent> output, IReadOnlyList<TimelineEvent> evidence, ref int nextId, string action, string summary, EventSeverity severity, string techniqueId, string techniqueName, string confidence)
    {
        if (evidence.Count == 0)
        {
            return;
        }

        int pid = evidence.First().Pid;
        if (output.Any(e => e.Category == EventCategory.Behavior && e.Pid == pid && e.Action == action))
        {
            return;
        }

        var raw = JsonSerializer.Serialize(new
        {
            source = "Behavior",
            action,
            technique_id = techniqueId,
            technique_name = techniqueName,
            confidence,
            evidence_event_ids = evidence.Select(e => e.Id).Take(40).ToArray(),
            evidence_actions = evidence.Select(e => e.Action).Distinct().Take(20).ToArray()
        }, JsonDefaults.Options);

        output.Add(new TimelineEvent(
            nextId++,
            evidence.Max(e => e.Time).Add(TimeSpan.FromMilliseconds(1)),
            evidence.FirstOrDefault(e => !string.IsNullOrWhiteSpace(e.Process))?.Process ?? "behavior",
            pid,
            EventCategory.Behavior,
            action,
            techniqueId,
            summary,
            severity,
            "Behavior",
            raw,
            techniqueId,
            techniqueName,
            confidence,
            evidence.FirstOrDefault(e => !string.IsNullOrWhiteSpace(e.ProcessGuid))?.ProcessGuid ?? ""));
    }

    private static bool HasAny(IReadOnlyList<TimelineEvent> events, IReadOnlyList<string> actions) =>
        events.Any(e => actions.Contains(e.Action, StringComparer.OrdinalIgnoreCase));

    private static bool ContainsAny(string value, params string[] needles) =>
        needles.Any(n => value.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static bool LooksRelativeDll(string value) =>
        value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !Path.IsPathFullyQualified(value);

    private static uint JsonNumber(string rawJson, string propertyName)
    {
        try
        {
            using var document = JsonDocument.Parse(rawJson);
            if (document.RootElement.TryGetProperty(propertyName, out var value) && value.TryGetUInt32(out uint parsed))
            {
                return parsed;
            }
        }
        catch
        {
            return 0;
        }

        return 0;
    }
}
