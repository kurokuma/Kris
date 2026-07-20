using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed class TraceEventEtwCollector
{
    /// <summary>Arms an ETW session before a target exists.  No event, network item, or callback is retained until BindTarget succeeds.</summary>
    public EtwArmedCapture Arm(
        EtwCollectorOptions options,
        CancellationToken cancellationToken = default,
        Action<TimelineEvent>? onEvent = null,
        Action<NetworkSession>? onNetworkSession = null)
    {
        var control = new EtwCaptureControl(options.TargetPid, discardUnboundRaw: true);
        var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var task = Task.Run(() =>
        {
            try { return CollectInternal(options with { TargetPid = null }, linked.Token, onEvent, onNetworkSession, control); }
            catch (Exception ex)
            {
                control.SetFailed(ex);
                return new EtwCollectionResult(false, false, "ETW pre-launch arm failed: " + ex.Message, [], []);
            }
        }, CancellationToken.None);
        return new EtwArmedCapture(control, linked, task);
    }

    public EtwCollectionResult Collect(EtwCollectorOptions options)
    {
        return Collect(options, CancellationToken.None);
    }

    public EtwCollectionResult Collect(EtwCollectorOptions options, CancellationToken cancellationToken)
    {
        return Collect(options, cancellationToken, null, null);
    }

    public EtwCollectionResult Collect(
        EtwCollectorOptions options,
        CancellationToken cancellationToken,
        Action<TimelineEvent>? onEvent,
        Action<NetworkSession>? onNetworkSession)
    {
        return CollectInternal(options, cancellationToken, onEvent, onNetworkSession, new EtwCaptureControl(options.TargetPid));
    }

    private EtwCollectionResult CollectInternal(
        EtwCollectorOptions options,
        CancellationToken cancellationToken,
        Action<TimelineEvent>? onEvent,
        Action<NetworkSession>? onNetworkSession,
        EtwCaptureControl control)
    {
        CaptureLimits.Validate(options.MaxPersistedEvents, options.MaxPersistedNetworkSessions, options.MaxRawTraceBytes);
        if (options.MaxScriptContentEvents is < 1 or > 10_000) throw new ArgumentOutOfRangeException(nameof(options.MaxScriptContentEvents));
        if (options.MaxScriptContentCharacters is < 256 or > 4 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(options.MaxScriptContentCharacters));
        string? validatedTracePath = ValidateRawTracePath(options.RawTracePath);
        if (!OperatingSystem.IsWindows())
        {
            control.SetFailed(new PlatformNotSupportedException("ETW is only available on Windows."));
            return new EtwCollectionResult(false, false, "ETW is only available on Windows.", Array.Empty<TimelineEvent>(), Array.Empty<NetworkSession>());
        }

        var events = new BoundedCaptureBuffer<TimelineEvent>(options.MaxPersistedEvents);
        var sessions = new BoundedCaptureBuffer<NetworkSession>(options.MaxPersistedNetworkSessions);
        var processNames = new ConcurrentDictionary<int, string>();
        var trackedPids = new PidTreeFilter(control.TargetPid);
        var startedAt = options.CaseStartedAtUtc ?? DateTimeOffset.UtcNow;
        int nextId = 1;
        string sessionName = "MRTW-" + Guid.NewGuid().ToString("N");
        int rawLimitReached = 0;
        string captureLimitReason = "";
        long scriptContentReceived = 0, scriptContentDropped = 0, scriptContentCharacters = 0;
        string scriptCaptureReason = "";
        string amsiProviderReason = "", powerShellProviderReason = "";
        long registryEventsReceived = 0, registryEventsDropped = 0, fileEventsReceived = 0, fileEventsDropped = 0;
        string registryCaptureReason = "", fileCaptureReason = "";

        try
        {
            string? tracePath = validatedTracePath;
            using var session = string.IsNullOrWhiteSpace(tracePath) ? new TraceEventSession(sessionName) : new TraceEventSession(sessionName, tracePath)
            {
                StopOnDispose = true
            };
            control.SetStop(() => session.Stop());

            bool CanCapture() => Volatile.Read(ref rawLimitReached) == 0;
            bool CaptureEvent(TimelineEvent item)
            {
                if (!CanCapture()) return false;
                if (events.TryAdd(item))
                {
                    try { onEvent?.Invoke(item); } catch { /* live callbacks must not stop ETW */ }
                    return true;
                }
                return false;
            }
            void CaptureNetworkSession(NetworkSession item)
            {
                if (!CanCapture()) return;
                if (sessions.TryAdd(item))
                {
                    try { onNetworkSession?.Invoke(item); } catch { /* live callbacks must not stop ETW */ }
                }
            }
            void StopForRawLimit()
            {
                if (Interlocked.CompareExchange(ref rawLimitReached, 1, 0) != 0) return;
                captureLimitReason = $"Raw ETL exceeded {options.MaxRawTraceBytes} bytes; raw and structured ETW capture stopped.";
                try { session.Stop(); } catch { }
            }

            var keywords = KernelTraceEventParser.Keywords.None;
            if (options.ProcessEvents)
            {
                keywords |= KernelTraceEventParser.Keywords.Process;
            }

            if (options.NetworkEvents)
            {
                keywords |= KernelTraceEventParser.Keywords.NetworkTCPIP;
            }

            if (options.ImageLoadEvents)
            {
                keywords |= KernelTraceEventParser.Keywords.ImageLoad;
            }
            if (options.RegistryEvents) keywords |= KernelTraceEventParser.Keywords.Registry;
            if (options.FileEvents) keywords |= KernelTraceEventParser.Keywords.FileIOInit;

            if (keywords != KernelTraceEventParser.Keywords.None)
            {
                session.EnableKernelProvider(keywords);
            }

            if (options.DnsEvents)
            {
                session.EnableProvider("Microsoft-Windows-DNS-Client");
            }
            if (options.ScriptEvents)
            {
                try { session.EnableProvider("Microsoft-Antimalware-Scan-Interface"); }
                catch (Exception ex) { amsiProviderReason = "AMSI provider unavailable: " + ex.Message; }
                try { session.EnableProvider("Microsoft-Windows-PowerShell"); }
                catch (Exception ex) { powerShellProviderReason = "PowerShell provider unavailable: " + ex.Message; }
            }

            control.SetReady();

            session.Source.Kernel.ProcessStart += data =>
            {
                if (!trackedPids.TrackStart(control.TargetPid, data.ParentID, data.ProcessID, options.FollowDescendants))
                {
                    return;
                }

                RememberProcessName(processNames, data.ProcessID, data.ProcessName, data.ImageFileName);
                CaptureEvent( Event(
                    Interlocked.Increment(ref nextId),
                    DateTimeOffset.Now - startedAt,
                    data.ProcessName,
                    data.ProcessID,
                    EventCategory.Process,
                    "Process Start",
                    data.ImageFileName,
                    $"Process started: {data.CommandLine}",
                    EventSeverity.Informational,
                    "ETW",
                    data));
            };

            session.Source.Kernel.ProcessStop += data =>
            {
                if (!trackedPids.Matches(control.TargetPid, data.ProcessID))
                {
                    return;
                }

                string processName = KnownProcessName(processNames, data.ProcessID, data.ProcessName, data.ImageFileName);
                CaptureEvent( Event(
                    Interlocked.Increment(ref nextId),
                    DateTimeOffset.Now - startedAt,
                    processName,
                    data.ProcessID,
                    EventCategory.Process,
                    "Process Exit",
                    data.ImageFileName,
                    $"Process exited: {data.ExitStatus}",
                    data.ExitStatus == 0 ? EventSeverity.Informational : EventSeverity.Medium,
                    "ETW",
                    data));
                trackedPids.Complete(control.TargetPid, data.ProcessID);
            };

            session.Source.Kernel.ImageLoad += data =>
            {
                if (!trackedPids.Matches(control.TargetPid, data.ProcessID))
                {
                    return;
                }

                RememberProcessName(processNames, data.ProcessID, null, data.FileName);
                CaptureEvent( Event(
                    Interlocked.Increment(ref nextId),
                    DateTimeOffset.Now - startedAt,
                    KnownProcessName(processNames, data.ProcessID, null, null),
                    data.ProcessID,
                    EventCategory.Module,
                    "Load",
                    data.FileName,
                    "Image loaded",
                    EventSeverity.Low,
                    "ETW",
                    data));
            };

            session.Source.Kernel.TcpIpConnect += data =>
            {
                if (!trackedPids.Matches(control.TargetPid, data.ProcessID))
                {
                    return;
                }

                string remote = $"{data.daddr}:{data.dport}";
                string process = KnownProcessName(processNames, data.ProcessID, null, null);
                CaptureEvent( Event(
                    Interlocked.Increment(ref nextId),
                    DateTimeOffset.Now - startedAt,
                    process,
                    data.ProcessID,
                    EventCategory.Network,
                    "TCP Connect",
                    remote,
                    "TCP connection observed by ETW",
                    EventSeverity.Medium,
                    "ETW",
                    data));
                CaptureNetworkSession( new NetworkSession(process, "-", "-", data.daddr.ToString(), data.dport, "TCP", DateTimeOffset.Now - startedAt, 0, 0, "-", "-"));
            };

            session.Source.Kernel.UdpIpSend += data =>
            {
                if (!trackedPids.Matches(control.TargetPid, data.ProcessID)) return;
                string remote = $"{data.daddr}:{data.dport}"; string process = KnownProcessName(processNames, data.ProcessID, null, null);
                CaptureEvent( Event(Interlocked.Increment(ref nextId), DateTimeOffset.UtcNow - startedAt, process, data.ProcessID, EventCategory.Network, "UDP Send", remote, "UDP metadata observed by kernel ETW", EventSeverity.Medium, "ETW", data));
                CaptureNetworkSession( new NetworkSession(process, "", "", data.daddr.ToString(), data.dport, "UDP", DateTimeOffset.UtcNow - startedAt, data.size, 0, "", "", Coverage: "kernel ETW UDP metadata; payload/TLS/JA3 unsupported"));
            };

            session.Source.Kernel.UdpIpRecv += data =>
            {
                if (!trackedPids.Matches(control.TargetPid, data.ProcessID)) return;
                string remote = $"{data.saddr}:{data.sport}"; string process = KnownProcessName(processNames, data.ProcessID, null, null);
                CaptureEvent( Event(Interlocked.Increment(ref nextId), DateTimeOffset.UtcNow - startedAt, process, data.ProcessID, EventCategory.Network, "UDP Receive", remote, "UDP metadata observed by kernel ETW", EventSeverity.Low, "ETW", data));
                CaptureNetworkSession( new NetworkSession(process, "", "", data.saddr.ToString(), data.sport, "UDP", DateTimeOffset.UtcNow - startedAt, 0, data.size, "", "", Coverage: "kernel ETW UDP metadata; payload/TLS/JA3 unsupported"));
            };

            if (options.DnsEvents || options.ScriptEvents || options.RegistryEvents || options.FileEvents)
            {
                session.Source.Dynamic.All += data =>
                {
                    if (options.DnsEvents && data.ProviderName.Equals("Microsoft-Windows-DNS-Client", StringComparison.OrdinalIgnoreCase))
                    {
                        int pid = data.ProcessID;
                        if (!trackedPids.Matches(control.TargetPid, pid)) return;
                        string query = TryPayload(data, "QueryName") ?? TryPayload(data, "Name") ?? data.EventName;
                        string answers = TryPayload(data, "QueryResults") ?? TryPayload(data, "Address") ?? "";
                        string status = TryPayload(data, "Status") ?? TryPayload(data, "Result") ?? "";
                        CaptureEvent(Event(Interlocked.Increment(ref nextId), DateTimeOffset.Now - startedAt, KnownProcessName(processNames, pid, null, null), pid, EventCategory.Dns, "DNS Query", query, $"DNS event observed by ETW; status={status}; answers={answers}", EventSeverity.Medium, "ETW", data.PayloadString(0)));
                        if (!string.IsNullOrWhiteSpace(query)) CaptureNetworkSession(new NetworkSession(KnownProcessName(processNames, pid, null, null), query, answers, "", 53, "DNS", DateTimeOffset.UtcNow - startedAt, 0, 0, "", "", status, answers, "DNS client ETW metadata"));
                        return;
                    }
                    int dynamicPid = data.ProcessID;
                    if (!trackedPids.Matches(control.TargetPid, dynamicPid)) return;
                    bool amsi = options.ScriptEvents && data.ProviderName.Equals("Microsoft-Antimalware-Scan-Interface", StringComparison.OrdinalIgnoreCase);
                    bool scriptBlock = options.ScriptEvents && data.ProviderName.Equals("Microsoft-Windows-PowerShell", StringComparison.OrdinalIgnoreCase) && (int)data.ID == 4104;
                    if (amsi || scriptBlock)
                    {
                        string content = TryPayload(data, "ScriptBlockText") ?? TryPayload(data, "Content") ?? TryPayload(data, "ScanContent") ?? "";
                        int remaining = Math.Max(0, options.MaxScriptContentCharacters - (int)Math.Min(int.MaxValue, Interlocked.Read(ref scriptContentCharacters)));
                        if (Interlocked.Read(ref scriptContentReceived) >= options.MaxScriptContentEvents || content.Length > remaining)
                        {
                            Interlocked.Increment(ref scriptContentDropped);
                            scriptCaptureReason = $"script-content-limit; events={options.MaxScriptContentEvents}; characters={options.MaxScriptContentCharacters}";
                            return;
                        }
                        bool retained = CaptureEvent(Event(Interlocked.Increment(ref nextId), DateTimeOffset.UtcNow - startedAt, KnownProcessName(processNames, dynamicPid, null, null), dynamicPid,
                            EventCategory.Api, amsi ? "AMSI Scan" : "PowerShell ScriptBlock", amsi ? data.EventName : "ScriptBlock",
                            amsi ? "AMSI scan observed by ETW." : "PowerShell ScriptBlock observed by ETW.", EventSeverity.Medium, "ETW",
                            new { provider = data.ProviderName, event_id = data.ID, content }));
                        if (retained)
                        {
                            Interlocked.Increment(ref scriptContentReceived);
                            Interlocked.Add(ref scriptContentCharacters, content.Length);
                        }
                        else
                        {
                            Interlocked.Increment(ref scriptContentDropped);
                            scriptCaptureReason = "global-event-limit; script content was not persisted.";
                        }
                        return;
                    }

                    bool registry = options.RegistryEvents && data.ProviderName.Contains("Kernel-Registry", StringComparison.OrdinalIgnoreCase);
                    bool file = options.FileEvents && data.ProviderName.Contains("Kernel-File", StringComparison.OrdinalIgnoreCase);
                    if (!registry && !file) return;
                    string target = TryPayload(data, "KeyName") ?? TryPayload(data, "FileName") ?? TryPayload(data, "FilePath") ?? data.EventName;
                    if (registry) Interlocked.Increment(ref registryEventsReceived); else Interlocked.Increment(ref fileEventsReceived);
                    bool surfaceRetained = CaptureEvent(Event(Interlocked.Increment(ref nextId), DateTimeOffset.UtcNow - startedAt, KnownProcessName(processNames, dynamicPid, null, null), dynamicPid,
                        registry ? EventCategory.Registry : EventCategory.File, data.EventName, target,
                        $"{(registry ? "Registry" : "File")} event observed by kernel ETW.", EventSeverity.Low, "ETW", data));
                    if (!surfaceRetained)
                    {
                        if (registry)
                        {
                            Interlocked.Increment(ref registryEventsDropped);
                            registryCaptureReason = "global-event-limit; registry event was not persisted.";
                        }
                        else
                        {
                            Interlocked.Increment(ref fileEventsDropped);
                            fileCaptureReason = "global-event-limit; file event was not persisted.";
                        }
                    }
                };
            }

            using var rawLimitTimer = string.IsNullOrWhiteSpace(tracePath) ? null : new Timer(_ =>
            {
                try
                {
                    if (File.Exists(tracePath) && new FileInfo(tracePath).Length > options.MaxRawTraceBytes) StopForRawLimit();
                }
                catch { /* best effort only; ETW collection remains usable */ }
            }, null, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250));
            using var durationTimer = options.Duration is null ? null : new Timer(_ => session.Stop(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            if (options.Duration is not null)
            {
                _ = control.Bound.ContinueWith(_ => durationTimer?.Change(options.Duration.Value, Timeout.InfiniteTimeSpan),
                    CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);
            }
            using var cancellationRegistration = cancellationToken.Register(() => session.Stop());
            session.Source.Process();

            long rawBytes = !string.IsNullOrWhiteSpace(tracePath) && File.Exists(tracePath) ? new FileInfo(tracePath).Length : 0;
            bool discardUnboundRaw = control.DiscardUnboundRaw && !control.TargetPid.HasValue;
            if (rawLimitReached != 0)
            {
                rawLimitTimer?.Dispose();
                durationTimer?.Dispose();
                cancellationRegistration.Dispose();
                session.Dispose();
                captureLimitReason += " " + TryDeleteBoundedRawTrace(tracePath);
            }
            if (discardUnboundRaw)
            {
                captureLimitReason += " Target PID was never bound; pre-bind raw ETL was discarded. " + TryDeleteBoundedRawTrace(tracePath);
            }
            string? retainedRawTrace = rawLimitReached == 0 && !discardUnboundRaw ? tracePath : null;
            return new EtwCollectionResult(true, true, null, events.ToArray().OrderBy(e => e.Time).ToArray(), sessions.ToArray(), retainedRawTrace,
                events.Received, events.Dropped, sessions.Received, sessions.Dropped, rawBytes, options.MaxRawTraceBytes, captureLimitReason, control.TargetPid.HasValue,
                scriptContentReceived, scriptContentDropped, scriptContentCharacters, scriptCaptureReason, amsiProviderReason, powerShellProviderReason,
                registryEventsReceived, registryEventsDropped, registryCaptureReason, fileEventsReceived, fileEventsDropped, fileCaptureReason);
        }
        catch (Exception ex)
        {
            control.SetFailed(ex);
            long rawBytes = !string.IsNullOrWhiteSpace(validatedTracePath) && File.Exists(validatedTracePath) ? new FileInfo(validatedTracePath).Length : 0;
            bool discardUnboundRaw = control.DiscardUnboundRaw && !control.TargetPid.HasValue;
            if (rawLimitReached != 0) captureLimitReason += " " + TryDeleteBoundedRawTrace(validatedTracePath);
            if (discardUnboundRaw)
                captureLimitReason += " Target PID was never bound; pre-bind raw ETL was discarded. " + TryDeleteBoundedRawTrace(validatedTracePath);
            string? retainedRawTrace = rawLimitReached == 0 && !discardUnboundRaw ? validatedTracePath : null;
            return new EtwCollectionResult(false, false, ex.Message, events.ToArray().OrderBy(e => e.Time).ToArray(), sessions.ToArray(), retainedRawTrace,
                events.Received, events.Dropped, sessions.Received, sessions.Dropped, rawBytes, options.MaxRawTraceBytes, captureLimitReason, control.TargetPid.HasValue,
                scriptContentReceived, scriptContentDropped, scriptContentCharacters, scriptCaptureReason, amsiProviderReason, powerShellProviderReason,
                registryEventsReceived, registryEventsDropped, registryCaptureReason, fileEventsReceived, fileEventsDropped, fileCaptureReason);
        }
    }

    /// <summary>Rejects raw ETL output outside MRTW's case-specific scratch area.</summary>
    public static string? ValidateRawTracePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "MRTW"));
            string full = Path.GetFullPath(path);
            string relative = Path.GetRelativePath(root, full);
            string[] parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (parts.Length != 3 || !parts[0].StartsWith("case-", StringComparison.Ordinal) || !parts[1].Equals("raw_evidence", StringComparison.OrdinalIgnoreCase) ||
                relative.StartsWith("..", StringComparison.Ordinal) || Path.GetFileName(full) != parts[2])
                throw new InvalidOperationException("Raw ETL output must be directly under %TEMP%\\MRTW\\case-*\\raw_evidence.");

            string caseDirectory = Path.Combine(root, parts[0]);
            string parent = Path.Combine(caseDirectory, parts[1]);
            if (!Path.GetDirectoryName(full)!.Equals(parent, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Raw ETL output must not traverse outside the trusted scratch area.");
            EnsureTrustedDirectory(root);
            EnsureTrustedDirectory(caseDirectory);
            EnsureTrustedDirectory(parent);
            if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Raw ETL output file is a reparse point.");
            return full;
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception ex) { throw new InvalidOperationException("Raw ETL output path could not be validated.", ex); }
        throw new InvalidOperationException("Raw ETL output is outside the trusted scratch area.");
    }

    private static void EnsureTrustedDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Raw ETL output path contains a reparse point.");
            return;
        }

        Directory.CreateDirectory(path);
        if (!Directory.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Raw ETL output directory could not be created safely.");
    }

    private static string TryDeleteBoundedRawTrace(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "Raw ETL cleanup skipped: no path.";
        try
        {
            string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "MRTW"));
            string full = Path.GetFullPath(path);
            string relative = Path.GetRelativePath(root, full);
            string[] parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (parts.Length != 3 || !parts[0].StartsWith("case-", StringComparison.Ordinal) || !parts[1].Equals("raw_evidence", StringComparison.OrdinalIgnoreCase) ||
                relative.StartsWith("..", StringComparison.Ordinal) || Path.GetFileName(full) != parts[2])
                return "Raw ETL cleanup skipped: path is outside the trusted case scratch area.";

            var info = new FileInfo(full);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0) return "Raw ETL cleanup skipped: file is unavailable or unsafe.";
            for (DirectoryInfo? directory = info.Directory; directory is not null; directory = directory.Parent)
            {
                if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) return "Raw ETL cleanup skipped: scratch path contains a reparse point.";
                if (directory.FullName.Equals(root, StringComparison.OrdinalIgnoreCase)) break;
            }
            File.Delete(full);
            return "Raw ETL cleanup succeeded after the capture limit.";
        }
        catch (Exception ex) { return $"Raw ETL cleanup failed: {ex.Message}"; }
    }

    private static void RememberProcessName(ConcurrentDictionary<int, string> names, int pid, string? processName, string? imagePath)
    {
        string resolved = ResolveProcessName(pid, processName, imagePath);
        if (!string.IsNullOrWhiteSpace(resolved) && !resolved.StartsWith("pid-", StringComparison.OrdinalIgnoreCase))
        {
            names[pid] = resolved;
        }
    }

    private static string KnownProcessName(ConcurrentDictionary<int, string> names, int pid, string? processName, string? imagePath)
    {
        string resolved = ResolveProcessName(pid, processName, imagePath);
        if (!resolved.StartsWith("pid-", StringComparison.OrdinalIgnoreCase))
        {
            names[pid] = resolved;
            return resolved;
        }

        return names.TryGetValue(pid, out string? cached) ? cached : resolved;
    }

    private static string ResolveProcessName(int pid, string? processName, string? imagePath)
    {
        if (!string.IsNullOrWhiteSpace(processName))
        {
            return processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? processName : processName + ".exe";
        }

        if (!string.IsNullOrWhiteSpace(imagePath))
        {
            string fileName = Path.GetFileName(imagePath);
            if (!string.IsNullOrWhiteSpace(fileName))
            {
                return fileName;
            }
        }

        return ProcessName(pid);
    }

    private static string ProcessName(int pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return process.ProcessName + ".exe";
        }
        catch
        {
            return "pid-" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    private static string? TryPayload(Microsoft.Diagnostics.Tracing.TraceEvent data, string name)
    {
        try
        {
            object? value = data.PayloadByName(name);
            return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
        }
        catch
        {
            return null;
        }
    }

    private static TimelineEvent Event(int id, TimeSpan time, string process, int pid, EventCategory category, string action, string obj, string summary, EventSeverity severity, string source, object raw)
    {
        string rawJson;
        try
        {
            rawJson = JsonSerializer.Serialize(raw, JsonDefaults.Options);
        }
        catch
        {
            rawJson = JsonSerializer.Serialize(new { source, category = category.ToString(), action, obj, summary }, JsonDefaults.Options);
        }

        return new TimelineEvent(id, time < TimeSpan.Zero ? TimeSpan.Zero : time, process, pid, category, action, obj, summary, severity, source, rawJson, CapturedAtUtc: DateTimeOffset.UtcNow);
    }
}

/// <summary>Tracks only a bound root and live descendants; exited children are removed to reject PID reuse.</summary>
internal sealed class PidTreeFilter
{
    private readonly ConcurrentDictionary<int, byte> _tracked = new();

    public PidTreeFilter(int? rootPid)
    {
        if (rootPid is int pid && pid > 0) _tracked.TryAdd(pid, 0);
    }

    public bool TrackStart(int? rootPid, int parentPid, int pid, bool followDescendants)
    {
        if (!rootPid.HasValue || pid <= 0) return false;
        if (pid == rootPid.Value) _tracked.TryAdd(pid, 0);
        else if (followDescendants && _tracked.ContainsKey(parentPid)) _tracked.TryAdd(pid, 0);
        return _tracked.ContainsKey(pid);
    }

    public bool Matches(int? rootPid, int pid)
    {
        if (!rootPid.HasValue || pid <= 0) return false;
        if (pid == rootPid.Value) _tracked.TryAdd(pid, 0);
        return _tracked.ContainsKey(pid);
    }

    public void Complete(int? rootPid, int pid)
    {
        if (rootPid.HasValue && pid != rootPid.Value) _tracked.TryRemove(pid, out _);
    }
}

/// <summary>Owns one pre-launch ETW capture. Dispose/Stop are idempotent.</summary>
public sealed class EtwArmedCapture : IDisposable
{
    private readonly EtwCaptureControl _control;
    private readonly CancellationTokenSource _cancellation;
    private int _stopped;

    internal EtwArmedCapture(EtwCaptureControl control, CancellationTokenSource cancellation, Task<EtwCollectionResult> completion)
    {
        _control = control;
        _cancellation = cancellation;
        Completion = completion;
    }

    public Task Ready => _control.Ready.Task;
    public Task<EtwCollectionResult> Completion { get; }
    public bool BindTarget(int pid) => _control.BindTarget(pid);
    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
        _cancellation.Cancel();
        _control.Stop();
    }
    public void Dispose() { Stop(); _cancellation.Dispose(); }
}

internal sealed class EtwCaptureControl
{
    private readonly TaskCompletionSource<bool> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<int> _bound = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Action? _stop;
    private int _targetPid;

    public EtwCaptureControl(int? targetPid, bool discardUnboundRaw = false)
    {
        DiscardUnboundRaw = discardUnboundRaw;
        if (targetPid is int pid && pid > 0) BindTarget(pid);
    }
    public bool DiscardUnboundRaw { get; }
    public int? TargetPid => Volatile.Read(ref _targetPid) is int pid and > 0 ? pid : null;
    public TaskCompletionSource<bool> Ready => _ready;
    public Task<int> Bound => _bound.Task;
    public bool IsBound => TargetPid.HasValue;
    public bool BindTarget(int pid)
    {
        if (pid <= 0) return false;
        if (Interlocked.CompareExchange(ref _targetPid, pid, 0) != 0) return Volatile.Read(ref _targetPid) == pid;
        _bound.TrySetResult(pid);
        return true;
    }
    public void SetStop(Action stop) { _stop = stop; }
    public void Stop() { try { Volatile.Read(ref _stop)?.Invoke(); } catch { } }
    public void SetReady() => _ready.TrySetResult(true);
    public void SetFailed(Exception error) => _ready.TrySetException(error);
}
