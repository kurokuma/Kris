using System.Diagnostics;
using System.ComponentModel;
using System.Net;
using System.Text;
using System.Text.Json;

namespace MRTW.Core;

public sealed class RuntimeCaseCollector
{
    private const int ErrorElevationRequired = 740;
    private readonly SnapshotService _snapshot = new();

    public CaseData Collect(ExecutionProfile profile, StaticAnalysisResult? staticAnalysis)
    {
        return Collect(profile, staticAnalysis, CancellationToken.None);
    }

    public CaseData Collect(ExecutionProfile profile, StaticAnalysisResult? staticAnalysis, CancellationToken cancellationToken)
    {
        return Collect(profile, staticAnalysis, cancellationToken, null);
    }

    public CaseData Collect(ExecutionProfile profile, StaticAnalysisResult? staticAnalysis, CancellationToken cancellationToken, Action<TimelineEvent>? onEvent)
    {
        return Collect(profile, staticAnalysis, cancellationToken, onEvent, null);
    }

    public CaseData Collect(ExecutionProfile profile, StaticAnalysisResult? staticAnalysis, CancellationToken cancellationToken, Action<TimelineEvent>? onEvent, CollectionRunContext? runContext)
    {
        runContext ??= CollectionRunContext.Create();
        string caseId = runContext.CaseId;
        var started = runContext.StartedAtUtc;
        var events = new List<TimelineEvent>();
        var processes = new List<ProcessNode>();
        var networks = new List<NetworkSession>();
        int nextId = 1;
        HookPipeServer? hookPipe = null;
        int callbackFailures = 0;

        SnapshotData before = profile.SnapshotBefore ? _snapshot.Capture(profile) : EmptySnapshot();
        var seenTcpConnections = before.TcpConnections.ToHashSet(StringComparer.OrdinalIgnoreCase);
        Process? process = null;
        int? pid = null;
        DateTimeOffset? processStarted = null;
        DateTimeOffset? processExited = null;
        int exitCode = 0;
        bool processExitReported = false;

        void Add(TimelineEvent timelineEvent)
        {
            events.Add(timelineEvent);
            try
            {
                onEvent?.Invoke(timelineEvent);
            }
            catch
            {
                callbackFailures++;
            }
        }

        void AddMany(IEnumerable<TimelineEvent> timelineEvents)
        {
            foreach (var timelineEvent in timelineEvents)
            {
                Add(timelineEvent);
            }
        }

        void PollNetworkConnections()
        {
            foreach (string connection in SnapshotService.CaptureTcpConnections())
            {
                if (!seenTcpConnections.Add(connection))
                {
                    continue;
                }

                var parsed = ParseConnection(connection);
                networks.Add(new NetworkSession("system", "-", "-", parsed.RemoteHost, parsed.RemotePort, "TCP", DateTimeOffset.Now - started, 0, 0, "-", "-"));
                Add(Event(nextId++, DateTimeOffset.Now - started, "system", 0, EventCategory.Network, "TCP Connect", $"{parsed.RemoteHost}:{parsed.RemotePort}", connection, EventSeverity.Low, "NetworkSnapshot"));
            }
        }

        if (profile.ExecuteTarget)
        {
            try
            {
                var nativeHook = new NativeHookLauncher();
                bool hookSupported = IsNativeHookSupported(profile, staticAnalysis);
                if (profile.EnableHook && nativeHook.IsAvailable && hookSupported)
                {
                    hookPipe = new HookPipeServer();
                    hookPipe.Start();
                    processStarted = DateTimeOffset.Now;
                    Add(Event(nextId++, processStarted.Value - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Process, "Hooked Process Start", profile.CommandLine, "Target launched through native injector", EventSeverity.Informational, "ExecutionManager"));
                    using var injector = Process.Start(nativeHook.CreateStartInfo(profile, hookPipe.FullPipeName));
                    if (injector is null)
                    {
                        throw new InvalidOperationException("Native injector could not be started.");
                    }

                    int observedInjectedPid = 0;
                    bool processAttachedReported = false;
                    var outputBuilder = new StringBuilder();
                    var errorBuilder = new StringBuilder();
                    injector.OutputDataReceived += (_, args) =>
                    {
                        if (args.Data is not null)
                        {
                            outputBuilder.AppendLine(args.Data);
                            int parsedPid = TryReadInjectedPid(args.Data);
                            if (parsedPid > 0)
                            {
                                observedInjectedPid = parsedPid;
                            }
                        }
                    };
                    injector.ErrorDataReceived += (_, args) =>
                    {
                        if (args.Data is not null)
                        {
                            errorBuilder.AppendLine(args.Data);
                        }
                    };
                    injector.BeginOutputReadLine();
                    injector.BeginErrorReadLine();
                    bool injectorExited = false;
                    var injectorWait = Stopwatch.StartNew();
                    while (injectorWait.Elapsed < TimeSpan.FromSeconds(20))
                    {
                        if (injector.WaitForExit(100))
                        {
                            injectorExited = true;
                            break;
                        }

                        AddMany(hookPipe.DrainEvents(started, ref nextId));
                        PollNetworkConnections();
                        if (observedInjectedPid > 0 && process is null)
                        {
                            pid = observedInjectedPid;
                            process = TryGetProcessById(observedInjectedPid);
                            if (process is not null)
                            {
                                Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, "Process Attached", profile.CommandLine, "Target process located while native injector is still initializing", EventSeverity.Informational, "ExecutionManager"));
                                processAttachedReported = true;
                            }
                        }

                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                    }

                    if (injectorExited)
                    {
                        injector.WaitForExit();
                    }

                    string output = outputBuilder.ToString();
                    string error = errorBuilder.ToString();
                    int injectorExitCode = injectorExited ? SafeExitCode(injector) : -1;
                    if (!injectorExited)
                    {
                        Add(Event(nextId++, DateTimeOffset.Now - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Api, "Hook Injection Timeout", nativeHook.HookDllPath, "Injector did not finish within 20 seconds; continuing with non-hook telemetry.", EventSeverity.High, "Injector"));
                        TryKill(injector, false);
                    }
                    else if (injectorExitCode != 0)
                    {
                        Add(Event(nextId++, DateTimeOffset.Now - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Api, "Hook Injection Failed", nativeHook.HookDllPath, string.IsNullOrWhiteSpace(output + error) ? $"Injector exit code {injectorExitCode}" : output + error, EventSeverity.High, "Injector"));
                        if (IsElevationRequiredInjection(output, error, injectorExitCode))
                        {
                            Add(Event(
                                nextId++,
                                DateTimeOffset.Now - started,
                                Path.GetFileName(profile.TargetPath),
                                0,
                                EventCategory.Process,
                                "Elevation Required",
                                profile.TargetPath,
                                "Target requires administrator elevation. Native hook capture requires MRTW itself to be started as administrator; falling back to elevated non-hook execution when Windows allows it.",
                                EventSeverity.High,
                                "ExecutionManager"));
                        }
                    }

                    int injectedPid = observedInjectedPid > 0 ? observedInjectedPid : TryReadInjectedPid(output);
                    if ((!injectorExited || injectorExitCode != 0) && injectedPid == 0)
                    {
                        Add(Event(nextId++, DateTimeOffset.Now - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Process, "Hook Fallback Start", profile.CommandLine, "Native hook injection did not produce a target PID; starting target without hook.", EventSeverity.Medium, "ExecutionManager"));
                        process = StartProcess(profile);
                        pid = process.Id;
                        processStarted = DateTimeOffset.Now;
                    }

                    if (injectedPid > 0 && process is null)
                    {
                        pid = injectedPid;
                        process = TryGetProcessById(injectedPid);
                        if (process is null)
                        {
                            processExited = DateTimeOffset.Now;
                            processExitReported = true;
                            Add(Event(nextId++, processExited.Value - started, Path.GetFileName(profile.TargetPath), injectedPid, EventCategory.Process, "Process Exit", profile.CommandLine, "Target process exited before MRTW could attach an exit-code monitor", EventSeverity.Low, "ExecutionManager"));
                        }
                    }
                    else if (injectedPid > 0)
                    {
                        pid = injectedPid;
                    }

                    process ??= TryFindLaunchedProcess(profile, processStarted.Value);
                    if (process is not null && !processAttachedReported)
                    {
                        pid = process.Id;
                        Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, "Process Attached", profile.CommandLine, "Target process located after native injection", EventSeverity.Informational, "ExecutionManager"));
                    }

                    var waitOutcome = WaitForMonitoring(process, ProfileDuration(profile), cancellationToken, () =>
                    {
                        AddMany(hookPipe.DrainEvents(started, ref nextId));
                        PollNetworkConnections();
                        if (process is not null && !SafeHasExited(process))
                        {
                            SafeRefresh(process);
                        }
                        if (process is not null && SafeHasExited(process) && !processExitReported)
                        {
                            processExited = DateTimeOffset.Now;
                            exitCode = SafeExitCode(process);
                            processExitReported = true;
                            Add(Event(nextId++, processExited.Value - started, SafeProcessName(process, profile), pid ?? process.Id, EventCategory.Process, LauncherExitAction(staticAnalysis, exitCode), profile.CommandLine, ExitSummary(staticAnalysis, exitCode), exitCode == 0 ? EventSeverity.Informational : EventSeverity.Medium, "ExecutionManager"));
                        }
                    });
                    AddMany(hookPipe.DrainEvents(started, ref nextId));
                    PollNetworkConnections();
                    if (process is not null)
                    {
                        SafeRefresh(process);
                        if (SafeHasExited(process) && !processExitReported)
                        {
                            processExited = DateTimeOffset.Now;
                            exitCode = SafeExitCode(process);
                            processExitReported = true;
                            Add(Event(nextId++, processExited.Value - started, SafeProcessName(process, profile), pid ?? process.Id, EventCategory.Process, LauncherExitAction(staticAnalysis, exitCode), profile.CommandLine, ExitSummary(staticAnalysis, exitCode), exitCode == 0 ? EventSeverity.Informational : EventSeverity.Medium, "ExecutionManager"));
                        }
                        else if (waitOutcome == WaitOutcome.Canceled)
                        {
                            TryKill(process, profile.KillTree);
                            Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid ?? process.Id, EventCategory.Process, "User Stop", profile.CommandLine, "Process tree stopped by user request", EventSeverity.Low, "ExecutionManager"));
                        }
                        else if (waitOutcome == WaitOutcome.TimedOut && profile.TimeoutAction.Equals("kill", StringComparison.OrdinalIgnoreCase))
                        {
                            TryKill(process, profile.KillTree);
                            Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid ?? process.Id, EventCategory.Process, "Timeout Kill", profile.CommandLine, "Process tree killed after timeout", EventSeverity.Medium, "ExecutionManager"));
                        }
                    }
                }
                else
                {
                    if (profile.EnableHook && !hookSupported)
                    {
                        Add(Event(nextId++, DateTimeOffset.Now - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Api, "Hook Skipped", staticAnalysis?.Architecture ?? "unknown", NativeHookSkipSummary(staticAnalysis), EventSeverity.Medium, "ExecutionManager"));
                    }
                    else if (profile.EnableHook)
                    {
                        Add(Event(nextId++, DateTimeOffset.Now - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Api, "Hook Unavailable", "native\\hook_x64.dll", "Native hook binaries were not found; falling back to standard process execution.", EventSeverity.Medium, "ExecutionManager"));
                    }

                    process = StartProcess(profile);
                    pid = process.Id;
                    processStarted = DateTimeOffset.Now;
                    Add(Event(nextId++, processStarted.Value - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, "Process Start", profile.CommandLine, "Process started", EventSeverity.Informational, "ExecutionManager"));

                    var waitOutcome = WaitForExit(process, ProfileDuration(profile), cancellationToken, PollNetworkConnections);
                    if (waitOutcome != WaitOutcome.Exited)
                    {
                        if (waitOutcome == WaitOutcome.Canceled)
                        {
                            TryKill(process, profile.KillTree);
                            Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, "User Stop", profile.CommandLine, "Process tree stopped by user request", EventSeverity.Low, "ExecutionManager"));
                        }
                        else if (profile.TimeoutAction.Equals("kill", StringComparison.OrdinalIgnoreCase))
                        {
                            TryKill(process, profile.KillTree);
                            Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, "Timeout Kill", profile.CommandLine, "Process tree killed after timeout", EventSeverity.Medium, "ExecutionManager"));
                        }
                        else
                        {
                            Add(Event(nextId++, DateTimeOffset.Now - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, "Timeout Stop", profile.CommandLine, "Collection stopped after timeout", EventSeverity.Low, "ExecutionManager"));
                        }
                    }

                    SafeRefresh(process);
                    if (SafeHasExited(process))
                    {
                        processExited = DateTimeOffset.Now;
                        exitCode = SafeExitCode(process);
                        Add(Event(nextId++, processExited.Value - started, SafeProcessName(process, profile), pid.Value, EventCategory.Process, LauncherExitAction(staticAnalysis, exitCode), profile.CommandLine, ExitSummary(staticAnalysis, exitCode), exitCode == 0 ? EventSeverity.Informational : EventSeverity.Medium, "ExecutionManager"));
                    }
                }
            }
            catch (Exception ex)
            {
                Add(Event(nextId++, DateTimeOffset.Now - started, Path.GetFileName(profile.TargetPath), 0, EventCategory.Process, "Execution Failed", profile.CommandLine, ex.Message, EventSeverity.High, "ExecutionManager"));
            }
            finally
            {
                process?.Dispose();
                if (hookPipe is not null)
                {
                    AddMany(hookPipe.DrainEvents(started, ref nextId));
                    long transportFailures = hookPipe.ParseFailures + hookPipe.ConnectionFailures;
                    Add(Event(nextId++, DateTimeOffset.UtcNow - started, "hook", pid ?? 0, EventCategory.Api,
                        "Hook Transport Summary",
                        $"received={hookPipe.ReceivedLines};parse_failures={hookPipe.ParseFailures};connection_failures={hookPipe.ConnectionFailures}",
                        transportFailures == 0 ? "Hook pipe transport completed without observed loss." : "Hook pipe transport reported failures; the case may be incomplete.",
                        transportFailures == 0 ? EventSeverity.Informational : EventSeverity.High,
                        "Hook"));
                    hookPipe.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            }
        }
        else
        {
            Add(Event(nextId++, TimeSpan.Zero, Path.GetFileName(profile.TargetPath), 0, EventCategory.Process, "Execution Skipped", profile.TargetPath, "Execution disabled by profile", EventSeverity.Low, "ExecutionManager"));
        }

        SnapshotData after = profile.SnapshotAfter ? _snapshot.Capture(profile) : EmptySnapshot();
        SnapshotDiff diff = _snapshot.Diff(before, after);
        AddSnapshotEvents(Add, diff, started, ref nextId);
        AddNetworkEvents(Add, networks, diff, seenTcpConnections, started, ref nextId);
        if (callbackFailures > 0)
        {
            events.Add(Event(nextId++, DateTimeOffset.UtcNow - started, "collector", 0, EventCategory.Api,
                "Live Callback Failures", callbackFailures.ToString(), "One or more live UI callbacks failed; persisted collection continued.", EventSeverity.Medium, "Runtime"));
        }

        processes.AddRange(BuildProcessNodes(caseId, events, profile, pid ?? 0, processStarted ?? started, processExited));
        events = AttachProcessGuids(events, processes, caseId, started);

        var correlatedEvents = BehaviorCorrelator.Correlate(events);
        correlatedEvents = AttachProcessGuids(correlatedEvents, processes, caseId, started);
        var artifacts = BuildArtifacts(correlatedEvents, processes, started);
        string sampleName = Path.GetFileName(profile.TargetPath);
        string sha = staticAnalysis?.Sha256 ?? "unknown";
        string notes = events.Any(e => e.Action == "Execution Failed")
            ? "The target could not be executed in this environment. Static analysis and snapshot telemetry were still preserved."
            : events.Any(e => e.Action == "Launcher Process Exit")
                ? "The target behaved like a Windows shell/app launcher and exited with code 0 after handoff. MRTW did not stop it; review shell activation, child process, ETW, and hook events for the continued behavior."
                : "The case contains process execution, snapshot diff, registry, file, and system TCP observations collected with the standard .NET runtime.";

        return new CaseData(
            caseId,
            $"{Path.GetFileNameWithoutExtension(sampleName)}_{sha[..Math.Min(8, sha.Length)]}_{DateTime.Now:yyyyMMdd_HHmmss}",
            sampleName,
            profile.TargetPath,
            sha,
            started,
            DateTimeOffset.Now - started,
            staticAnalysis,
            processes,
            correlatedEvents.OrderBy(e => e.Time).ToArray(),
            artifacts,
            networks,
            notes);
    }

    private static Process StartProcess(ExecutionProfile profile)
    {
        var startInfo = new ProcessStartInfo
        {
            WorkingDirectory = Directory.Exists(profile.WorkingDirectory) ? profile.WorkingDirectory : Environment.CurrentDirectory,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (profile.TargetType.Equals("dll", StringComparison.OrdinalIgnoreCase) && profile.Runner.Equals("rundll32", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.FileName = "rundll32.exe";
            startInfo.Arguments = $"\"{profile.TargetPath}\",{profile.ExportFunction}";
        }
        else if (profile.TargetType.Equals("command", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.FileName = Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe";
            startInfo.Arguments = "/d /c " + profile.CommandLine;
        }
        else
        {
            startInfo.FileName = profile.TargetPath;
            startInfo.Arguments = string.Empty;
        }

        try
        {
            return Process.Start(startInfo) ?? throw new InvalidOperationException("Process.Start returned null.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorElevationRequired)
        {
            return StartElevatedProcess(profile);
        }
    }

    private static Process StartElevatedProcess(ExecutionProfile profile)
    {
        var startInfo = new ProcessStartInfo
        {
            WorkingDirectory = Directory.Exists(profile.WorkingDirectory) ? profile.WorkingDirectory : Environment.CurrentDirectory,
            UseShellExecute = true,
            Verb = "runas"
        };

        if (profile.TargetType.Equals("dll", StringComparison.OrdinalIgnoreCase) && profile.Runner.Equals("rundll32", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.FileName = "rundll32.exe";
            startInfo.Arguments = $"\"{profile.TargetPath}\",{profile.ExportFunction}";
        }
        else if (profile.TargetType.Equals("command", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.FileName = Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe";
            startInfo.Arguments = "/d /c " + profile.CommandLine;
        }
        else
        {
            startInfo.FileName = profile.TargetPath;
            startInfo.Arguments = string.Empty;
        }

        return Process.Start(startInfo) ?? throw new InvalidOperationException("Elevated Process.Start returned null.");
    }

    private static bool IsNativeHookSupported(ExecutionProfile profile, StaticAnalysisResult? staticAnalysis)
    {
        if (profile.TargetType.Equals("command", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (LooksLikeShellLauncher(staticAnalysis))
        {
            return false;
        }

        string architecture = staticAnalysis?.Architecture ?? string.Empty;
        return architecture.StartsWith("x64", StringComparison.OrdinalIgnoreCase) ||
               architecture.Contains("PE32+", StringComparison.OrdinalIgnoreCase);
    }

    private static string NativeHookSkipSummary(StaticAnalysisResult? staticAnalysis) =>
        LooksLikeShellLauncher(staticAnalysis)
            ? "Target looks like a Windows shell/app launcher. Native hook injection is skipped because suspended launchers can fail to hand off to the packaged app; starting target without hook."
            : "Native hook is x64-only for this build; falling back to standard process execution.";

    private static string LauncherExitAction(StaticAnalysisResult? staticAnalysis, int exitCode) =>
        exitCode == 0 && LooksLikeShellLauncher(staticAnalysis) ? "Launcher Process Exit" : "Process Exit";

    private static string ExitSummary(StaticAnalysisResult? staticAnalysis, int exitCode) =>
        exitCode == 0 && LooksLikeShellLauncher(staticAnalysis)
            ? "Launcher process exited with code 0 after handing execution to Windows shell/app activation"
            : $"Process exited with code {exitCode}";

    private static bool LooksLikeShellLauncher(StaticAnalysisResult? staticAnalysis)
    {
        if (staticAnalysis is null)
        {
            return false;
        }

        bool importsShell = staticAnalysis.Imports.Any(i => i.Equals("SHELL32.dll", StringComparison.OrdinalIgnoreCase));
        bool hasShellManifest = staticAnalysis.SuspiciousStrings.Any(s =>
            s.Contains("Microsoft.Windows.Shell.", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("shell", StringComparison.OrdinalIgnoreCase) && s.Contains("app", StringComparison.OrdinalIgnoreCase));
        bool hasLauncherExport = staticAnalysis.Exports.Any(e =>
            e.Contains("Started", StringComparison.OrdinalIgnoreCase) ||
            e.Contains("Launch", StringComparison.OrdinalIgnoreCase) ||
            e.Contains("Activate", StringComparison.OrdinalIgnoreCase));

        return importsShell && (hasShellManifest || hasLauncherExport);
    }

    private static IReadOnlyList<ProcessNode> BuildProcessNodes(
        string caseId,
        IReadOnlyList<TimelineEvent> events,
        ExecutionProfile profile,
        int rootPid,
        DateTimeOffset rootStart,
        DateTimeOffset? rootExit)
    {
        var nodes = new Dictionary<int, ProcessNode>();
        string rootName = Path.GetFileName(profile.TargetPath);
        nodes[rootPid] = CreateProcessNode(caseId, events, rootName, rootPid, null, profile.CommandLine, profile.TargetPath, rootStart, rootExit);

        foreach (var e in events.Where(e => e.Action is "CreateProcessW" or "CreateProcessA"))
        {
            int childPid = JsonInt(e.RawJson, "child_pid");
            if (childPid <= 0 || nodes.ContainsKey(childPid))
            {
                continue;
            }

            string commandLine = JsonString(e.RawJson, "command_line");
            string application = JsonString(e.RawJson, "application");
            string imagePath = string.IsNullOrWhiteSpace(application) ? FirstCommandToken(commandLine) : application;
            string name = string.IsNullOrWhiteSpace(imagePath) ? $"pid-{childPid}" : Path.GetFileName(imagePath.Trim('"'));
            nodes[childPid] = CreateProcessNode(caseId, events, name, childPid, e.Pid > 0 ? e.Pid : rootPid, commandLine, imagePath, rootStart.Add(e.Time), null);
        }

        return nodes.Values
            .OrderBy(p => p.ParentPid.HasValue ? 1 : 0)
            .ThenBy(p => p.StartTime)
            .ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static ProcessNode CreateProcessNode(
        string caseId,
        IReadOnlyList<TimelineEvent> events,
        string name,
        int pid,
        int? parentPid,
        string commandLine,
        string imagePath,
        DateTimeOffset start,
        DateTimeOffset? end)
    {
        return new ProcessNode(
            name,
            pid,
            parentPid,
            StableProcessGuid(caseId, pid, start),
            commandLine,
            imagePath,
            start,
            end,
            events.Count(e => e.Pid == pid),
            events.Count(e => e.Pid == pid && e.Category == EventCategory.Network),
            events.Count(e => e.Pid == pid && e.Category == EventCategory.File),
            events.Count(e => e.Pid == pid && e.Category == EventCategory.Registry));
    }

    private static List<TimelineEvent> AttachProcessGuids(IReadOnlyList<TimelineEvent> events, IReadOnlyList<ProcessNode> processes, string caseId, DateTimeOffset fallbackStart)
    {
        var byPidAndName = processes
            .GroupBy(p => ProcessKey(p.Pid, p.Name))
            .ToDictionary(g => g.Key, g => g.OrderBy(p => p.StartTime).First(), StringComparer.OrdinalIgnoreCase);
        var uniqueByPid = processes
            .Where(p => p.Pid > 0)
            .GroupBy(p => p.Pid)
            .Where(g => g.Count() == 1)
            .ToDictionary(g => g.Key, g => g.First());

        return events.Select(e =>
        {
            if (!string.IsNullOrWhiteSpace(e.ProcessGuid))
            {
                return e;
            }

            if (byPidAndName.TryGetValue(ProcessKey(e.Pid, e.Process), out var process))
            {
                return e with { ProcessGuid = process.ProcessGuid };
            }

            if (e.Pid > 0 && uniqueByPid.TryGetValue(e.Pid, out process))
            {
                return e with { ProcessGuid = process.ProcessGuid };
            }

            return e with { ProcessGuid = StableProcessGuid(caseId, e.Pid, fallbackStart.Add(e.Time)) };
        }).ToList();
    }

    private static string StableProcessGuid(string caseId, int pid, DateTimeOffset start) =>
        $"{caseId}:{pid}:{start.UtcTicks}";

    private static string ProcessKey(int pid, string process) =>
        $"{pid}:{process}";

    private static string FirstCommandToken(string commandLine)
    {
        string trimmed = commandLine.Trim();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        if (trimmed[0] == '"')
        {
            int end = trimmed.IndexOf('"', 1);
            return end > 1 ? trimmed[1..end] : trimmed.Trim('"');
        }

        int space = trimmed.IndexOf(' ');
        return space > 0 ? trimmed[..space] : trimmed;
    }

    private static int JsonInt(string rawJson, string propertyName)
    {
        try
        {
            using var document = JsonDocument.Parse(rawJson);
            return document.RootElement.TryGetProperty(propertyName, out var value) && value.TryGetInt32(out int parsed) ? parsed : 0;
        }
        catch
        {
            return 0;
        }
    }

    private static string JsonString(string rawJson, string propertyName)
    {
        try
        {
            using var document = JsonDocument.Parse(rawJson);
            return document.RootElement.TryGetProperty(propertyName, out var value) ? value.GetString() ?? string.Empty : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static Process? TryFindLaunchedProcess(ExecutionProfile profile, DateTimeOffset processStarted)
    {
        string name = Path.GetFileNameWithoutExtension(profile.TargetPath);
        DateTime minStart = processStarted.LocalDateTime.AddSeconds(-2);
        foreach (var candidate in Process.GetProcessesByName(name).OrderByDescending(p => SafeStartTime(p)))
        {
            try
            {
                if (SafeStartTime(candidate) < minStart)
                {
                    candidate.Dispose();
                    continue;
                }

                string? path = SafeMainModulePath(candidate);
                if (path is not null && !string.Equals(path, profile.TargetPath, StringComparison.OrdinalIgnoreCase))
                {
                    candidate.Dispose();
                    continue;
                }

                return candidate;
            }
            catch
            {
                candidate.Dispose();
            }
        }

        return null;
    }

    private static int TryReadInjectedPid(string output)
    {
        foreach (string line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (root.TryGetProperty("event", out var evt) &&
                    (string.Equals(evt.GetString(), "injection_completed", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(evt.GetString(), "injection_failed", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(evt.GetString(), "process_created", StringComparison.OrdinalIgnoreCase)) &&
                    root.TryGetProperty("pid", out var pidValue) &&
                    pidValue.TryGetInt32(out int pid))
                {
                    return pid;
                }
            }
            catch
            {
                // Ignore non-JSON diagnostic output.
            }
        }

        return 0;
    }

    private static bool IsElevationRequiredInjection(string output, string error, int exitCode)
    {
        if (exitCode == ErrorElevationRequired)
        {
            return true;
        }

        foreach (string line in (output + "\n" + error).Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (root.TryGetProperty("win32_error", out var value) &&
                    value.TryGetInt32(out int parsed) &&
                    parsed == ErrorElevationRequired)
                {
                    return true;
                }
            }
            catch
            {
                // Ignore non-JSON diagnostic output.
            }
        }

        return false;
    }

    private static Process? TryGetProcessById(int processId)
    {
        try
        {
            return Process.GetProcessById(processId);
        }
        catch
        {
            return null;
        }
    }

    private static DateTime SafeStartTime(Process process)
    {
        try
        {
            return process.StartTime;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    private static string? SafeMainModulePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static void SafeRefresh(Process process)
    {
        try
        {
            process.Refresh();
        }
        catch
        {
            // Externally discovered or already-exited processes can reject refresh.
        }
    }

    private static bool SafeHasExited(Process process)
    {
        try
        {
            return process.HasExited;
        }
        catch
        {
            return true;
        }
    }

    private static int SafeExitCode(Process process)
    {
        try
        {
            return process.HasExited ? process.ExitCode : 0;
        }
        catch
        {
            return 0;
        }
    }

    private static void TryKill(Process process, bool entireTree)
    {
        try
        {
            process.Kill(entireTree);
        }
        catch
        {
            // The process may have exited between timeout detection and kill.
        }
    }

    private static TimeSpan? ProfileDuration(ExecutionProfile profile) =>
        profile.DurationSeconds is int seconds ? TimeSpan.FromSeconds(Math.Max(0, seconds)) : null;

    private enum WaitOutcome
    {
        Exited,
        Canceled,
        TimedOut
    }

    private static WaitOutcome WaitForExit(Process process, TimeSpan? duration, CancellationToken cancellationToken, Action onTick)
    {
        const int slice = 200;
        var deadline = duration is null ? (DateTimeOffset?)null : DateTimeOffset.Now.Add(duration.Value);
        while (true)
        {
            int wait = slice;
            if (deadline is not null)
            {
                var remaining = deadline.Value - DateTimeOffset.Now;
                if (remaining <= TimeSpan.Zero)
                {
                    return SafeHasExited(process) ? WaitOutcome.Exited : WaitOutcome.TimedOut;
                }

                wait = Math.Min(slice, (int)Math.Max(1, remaining.TotalMilliseconds));
            }

            if (process.WaitForExit(wait))
            {
                return WaitOutcome.Exited;
            }

            onTick();
            if (cancellationToken.IsCancellationRequested)
            {
                return WaitOutcome.Canceled;
            }
        }
    }

    private static WaitOutcome WaitForMonitoring(Process? process, TimeSpan? duration, CancellationToken cancellationToken, Action onTick)
    {
        const int slice = 200;
        var deadline = duration is null ? (DateTimeOffset?)null : DateTimeOffset.Now.Add(duration.Value);
        while (true)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return WaitOutcome.Canceled;
            }

            if (process is not null && SafeHasExited(process))
            {
                return WaitOutcome.Exited;
            }

            if (deadline is not null)
            {
                var remaining = deadline.Value - DateTimeOffset.Now;
                if (remaining <= TimeSpan.Zero)
                {
                    return process is not null && SafeHasExited(process) ? WaitOutcome.Exited : WaitOutcome.TimedOut;
                }

                Thread.Sleep(Math.Min(slice, (int)Math.Max(1, remaining.TotalMilliseconds)));
            }
            else
            {
                Thread.Sleep(slice);
            }

            onTick();
        }
    }

    private static string SafeProcessName(Process process, ExecutionProfile profile)
    {
        try
        {
            return process.ProcessName + ".exe";
        }
        catch
        {
            return Path.GetFileName(profile.TargetPath);
        }
    }

    private static void AddSnapshotEvents(Action<TimelineEvent> add, SnapshotDiff diff, DateTimeOffset started, ref int nextId)
    {
        foreach (var file in diff.AddedFiles.Take(80))
        {
            add(Event(nextId++, DateTimeOffset.Now - started, "snapshot", 0, EventCategory.File, "Create", file.Path, $"Created {file.Size} bytes", EventSeverity.Medium, "Snapshot"));
        }

        foreach (var file in diff.ModifiedFiles.Take(80))
        {
            add(Event(nextId++, DateTimeOffset.Now - started, "snapshot", 0, EventCategory.File, "Write", file.Path, $"Modified {file.Size} bytes", EventSeverity.Medium, "Snapshot"));
        }

        foreach (string file in diff.DeletedFiles.Take(40))
        {
            add(Event(nextId++, DateTimeOffset.Now - started, "snapshot", 0, EventCategory.File, "Delete", file, "Deleted file observed by snapshot diff", EventSeverity.Medium, "Snapshot"));
        }

        foreach (var value in diff.AddedRegistryValues.Take(40))
        {
            add(Event(nextId++, DateTimeOffset.Now - started, "snapshot", 0, EventCategory.Registry, "SetValue", $"{value.KeyPath}\\{value.Name}", value.Value, EventSeverity.High, "Snapshot"));
        }

        foreach (var value in diff.ModifiedRegistryValues.Take(40))
        {
            add(Event(nextId++, DateTimeOffset.Now - started, "snapshot", 0, EventCategory.Registry, "SetValue", $"{value.KeyPath}\\{value.Name}", "Modified registry value", EventSeverity.High, "Snapshot"));
        }

        foreach (string value in diff.DeletedRegistryValues.Take(20))
        {
            add(Event(nextId++, DateTimeOffset.Now - started, "snapshot", 0, EventCategory.Registry, "Delete", value, "Deleted registry value", EventSeverity.Medium, "Snapshot"));
        }
    }

    private static void AddNetworkEvents(Action<TimelineEvent> add, List<NetworkSession> networks, SnapshotDiff diff, HashSet<string> seenTcpConnections, DateTimeOffset started, ref int nextId)
    {
        foreach (string connection in diff.NewTcpConnections.Take(80))
        {
            if (!seenTcpConnections.Add(connection))
            {
                continue;
            }

            var parsed = ParseConnection(connection);
            networks.Add(new NetworkSession("system", "-", "-", parsed.RemoteHost, parsed.RemotePort, "TCP", DateTimeOffset.Now - started, 0, 0, "-", "-"));
            add(Event(nextId++, DateTimeOffset.Now - started, "system", 0, EventCategory.Network, "TCP Connect", $"{parsed.RemoteHost}:{parsed.RemotePort}", connection, EventSeverity.Low, "NetworkSnapshot"));
        }
    }

    private static (string RemoteHost, int RemotePort) ParseConnection(string connection)
    {
        int arrow = connection.IndexOf("->", StringComparison.Ordinal);
        string endpoint = arrow >= 0 ? connection[(arrow + 2)..].Split(' ')[0] : connection;
        if (IPEndPoint.TryParse(endpoint, out var parsed))
        {
            return (parsed.Address.ToString(), parsed.Port);
        }

        int colon = endpoint.LastIndexOf(':');
        if (colon > 0 && int.TryParse(endpoint[(colon + 1)..], out int port))
        {
            return (endpoint[..colon], port);
        }

        return (endpoint, 0);
    }

    private static IReadOnlyList<ArtifactItem> BuildArtifacts(IReadOnlyList<TimelineEvent> events, IReadOnlyList<ProcessNode> processes, DateTimeOffset started)
    {
        return events
            .Where(e => e.Category is EventCategory.File or EventCategory.Registry or EventCategory.Network or EventCategory.Dns or EventCategory.Api)
            .GroupBy(e => e.Category)
            .Select(g => new ArtifactItem(
                g.Key.ToString(),
                string.Join(", ", g.Select(e => e.ObjectValue).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
                started.Add(g.Min(e => e.Time)),
                started.Add(g.Max(e => e.Time)),
                g.Count(),
                string.Join(", ", processes.Select(p => p.Name).Distinct().Take(4)),
                g.Any(e => e.Severity is EventSeverity.Critical or EventSeverity.High) ? EventSeverity.High : g.Any(e => e.Severity == EventSeverity.Medium) ? EventSeverity.Medium : EventSeverity.Low))
            .OrderByDescending(a => a.EventCount)
            .ToArray();
    }

    private static TimelineEvent Event(int id, TimeSpan time, string process, int pid, EventCategory category, string action, string obj, string summary, EventSeverity severity, string source)
    {
        var raw = JsonSerializer.Serialize(new
        {
            id,
            timestamp = DateTimeOffset.Now,
            process = new { pid, name = process },
            category = category.ToString(),
            action,
            object_value = obj,
            summary,
            severity = severity.ToString(),
            source
        }, JsonDefaults.Options);

        var normalizedTime = time < TimeSpan.Zero ? TimeSpan.Zero : time;
        return new TimelineEvent(id, normalizedTime, process, pid, category, action, obj, summary, severity, source, raw, CapturedAtUtc: DateTimeOffset.UtcNow);
    }

    private static SnapshotData EmptySnapshot() => new(DateTimeOffset.UtcNow, Array.Empty<FileSnapshotEntry>(), Array.Empty<RegistrySnapshotEntry>(), Array.Empty<string>());
}
