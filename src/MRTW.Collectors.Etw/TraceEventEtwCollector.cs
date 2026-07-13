using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed class TraceEventEtwCollector
{
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
        CaptureLimits.Validate(options.MaxPersistedEvents, options.MaxPersistedNetworkSessions, options.MaxRawTraceBytes);
        string? validatedTracePath = ValidateRawTracePath(options.RawTracePath);
        if (!OperatingSystem.IsWindows())
        {
            return new EtwCollectionResult(false, false, "ETW is only available on Windows.", Array.Empty<TimelineEvent>(), Array.Empty<NetworkSession>());
        }

        var events = new BoundedCaptureBuffer<TimelineEvent>(options.MaxPersistedEvents);
        var sessions = new BoundedCaptureBuffer<NetworkSession>(options.MaxPersistedNetworkSessions);
        var processNames = new ConcurrentDictionary<int, string>();
        var trackedPids = new ConcurrentDictionary<int, byte>();
        if (options.TargetPid is int targetPid)
        {
            trackedPids[targetPid] = 0;
        }
        var startedAt = options.CaseStartedAtUtc ?? DateTimeOffset.UtcNow;
        int nextId = 1;
        string sessionName = "MRTW-" + Guid.NewGuid().ToString("N");
        int rawLimitReached = 0;
        string captureLimitReason = "";

        try
        {
            string? tracePath = validatedTracePath;
            using var session = string.IsNullOrWhiteSpace(tracePath) ? new TraceEventSession(sessionName) : new TraceEventSession(sessionName, tracePath)
            {
                StopOnDispose = true
            };

            bool CanCapture() => Volatile.Read(ref rawLimitReached) == 0;
            void CaptureEvent(TimelineEvent item)
            {
                if (!CanCapture()) return;
                if (events.TryAdd(item))
                {
                    try { onEvent?.Invoke(item); } catch { /* live callbacks must not stop ETW */ }
                }
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

            if (keywords != KernelTraceEventParser.Keywords.None)
            {
                session.EnableKernelProvider(keywords);
            }

            if (options.DnsEvents)
            {
                session.EnableProvider("Microsoft-Windows-DNS-Client");
            }

            session.Source.Kernel.ProcessStart += data =>
            {
                bool parentTracked = options.FollowDescendants && trackedPids.ContainsKey(data.ParentID);
                if (parentTracked)
                {
                    trackedPids[data.ProcessID] = 0;
                }
                if (!PidMatches(options.TargetPid, trackedPids, data.ProcessID))
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
                if (!PidMatches(options.TargetPid, trackedPids, data.ProcessID))
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
            };

            session.Source.Kernel.ImageLoad += data =>
            {
                if (!PidMatches(options.TargetPid, trackedPids, data.ProcessID))
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
                if (!PidMatches(options.TargetPid, trackedPids, data.ProcessID))
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
                if (!PidMatches(options.TargetPid, trackedPids, data.ProcessID)) return;
                string remote = $"{data.daddr}:{data.dport}"; string process = KnownProcessName(processNames, data.ProcessID, null, null);
                CaptureEvent( Event(Interlocked.Increment(ref nextId), DateTimeOffset.UtcNow - startedAt, process, data.ProcessID, EventCategory.Network, "UDP Send", remote, "UDP metadata observed by kernel ETW", EventSeverity.Medium, "ETW", data));
                CaptureNetworkSession( new NetworkSession(process, "", "", data.daddr.ToString(), data.dport, "UDP", DateTimeOffset.UtcNow - startedAt, data.size, 0, "", "", Coverage: "kernel ETW UDP metadata; payload/TLS/JA3 unsupported"));
            };

            session.Source.Kernel.UdpIpRecv += data =>
            {
                if (!PidMatches(options.TargetPid, trackedPids, data.ProcessID)) return;
                string remote = $"{data.saddr}:{data.sport}"; string process = KnownProcessName(processNames, data.ProcessID, null, null);
                CaptureEvent( Event(Interlocked.Increment(ref nextId), DateTimeOffset.UtcNow - startedAt, process, data.ProcessID, EventCategory.Network, "UDP Receive", remote, "UDP metadata observed by kernel ETW", EventSeverity.Low, "ETW", data));
                CaptureNetworkSession( new NetworkSession(process, "", "", data.saddr.ToString(), data.sport, "UDP", DateTimeOffset.UtcNow - startedAt, 0, data.size, "", "", Coverage: "kernel ETW UDP metadata; payload/TLS/JA3 unsupported"));
            };

            if (options.DnsEvents)
            {
                session.Source.Dynamic.All += data =>
                {
                    if (!data.ProviderName.Equals("Microsoft-Windows-DNS-Client", StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }

                    int pid = data.ProcessID;
                    if (!PidMatches(options.TargetPid, trackedPids, pid))
                    {
                        return;
                    }

                    string query = TryPayload(data, "QueryName") ?? TryPayload(data, "Name") ?? data.EventName;
                    string answers = TryPayload(data, "QueryResults") ?? TryPayload(data, "Address") ?? "";
                    string status = TryPayload(data, "Status") ?? TryPayload(data, "Result") ?? "";
                    CaptureEvent( Event(
                        Interlocked.Increment(ref nextId),
                        DateTimeOffset.Now - startedAt,
                        KnownProcessName(processNames, pid, null, null),
                        pid,
                        EventCategory.Dns,
                        "DNS Query",
                        query,
                        $"DNS event observed by ETW; status={status}; answers={answers}",
                        EventSeverity.Medium,
                        "ETW",
                        data.PayloadString(0)));
                    if (!string.IsNullOrWhiteSpace(query))
                    {
                        CaptureNetworkSession( new NetworkSession(
                            KnownProcessName(processNames, pid, null, null), query, answers, "", 53, "DNS",
                            DateTimeOffset.UtcNow - startedAt, 0, 0, "", "", status, answers, "DNS client ETW metadata"));
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
            using var durationTimer = options.Duration is null ? null : new Timer(_ => session.Stop(), null, options.Duration.Value, Timeout.InfiniteTimeSpan);
            using var cancellationRegistration = cancellationToken.Register(() => session.Stop());
            session.Source.Process();

            long rawBytes = !string.IsNullOrWhiteSpace(tracePath) && File.Exists(tracePath) ? new FileInfo(tracePath).Length : 0;
            if (rawLimitReached != 0)
            {
                rawLimitTimer?.Dispose();
                durationTimer?.Dispose();
                cancellationRegistration.Dispose();
                session.Dispose();
                captureLimitReason += " " + TryDeleteBoundedRawTrace(tracePath);
            }
            string? retainedRawTrace = rawLimitReached == 0 ? tracePath : null;
            return new EtwCollectionResult(true, true, null, events.ToArray().OrderBy(e => e.Time).ToArray(), sessions.ToArray(), retainedRawTrace,
                events.Received, events.Dropped, sessions.Received, sessions.Dropped, rawBytes, options.MaxRawTraceBytes, captureLimitReason);
        }
        catch (Exception ex)
        {
            long rawBytes = !string.IsNullOrWhiteSpace(validatedTracePath) && File.Exists(validatedTracePath) ? new FileInfo(validatedTracePath).Length : 0;
            if (rawLimitReached != 0) captureLimitReason += " " + TryDeleteBoundedRawTrace(validatedTracePath);
            string? retainedRawTrace = rawLimitReached == 0 ? validatedTracePath : null;
            return new EtwCollectionResult(false, false, ex.Message, events.ToArray().OrderBy(e => e.Time).ToArray(), sessions.ToArray(), retainedRawTrace,
                events.Received, events.Dropped, sessions.Received, sessions.Dropped, rawBytes, options.MaxRawTraceBytes, captureLimitReason);
        }
    }

    private static bool PidMatches(int? targetPid, ConcurrentDictionary<int, byte> trackedPids, int observedPid) =>
        !targetPid.HasValue || trackedPids.ContainsKey(observedPid);

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
