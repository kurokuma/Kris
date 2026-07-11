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
        if (!OperatingSystem.IsWindows())
        {
            return new EtwCollectionResult(false, false, "ETW is only available on Windows.", Array.Empty<TimelineEvent>(), Array.Empty<NetworkSession>());
        }

        var events = new ConcurrentQueue<TimelineEvent>();
        var sessions = new ConcurrentQueue<NetworkSession>();
        var processNames = new ConcurrentDictionary<int, string>();
        var trackedPids = new ConcurrentDictionary<int, byte>();
        if (options.TargetPid is int targetPid)
        {
            trackedPids[targetPid] = 0;
        }
        var startedAt = options.CaseStartedAtUtc ?? DateTimeOffset.UtcNow;
        int nextId = 1;
        string sessionName = "MRTW-" + Guid.NewGuid().ToString("N");

        try
        {
            using var session = new TraceEventSession(sessionName)
            {
                StopOnDispose = true
            };

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
                EnqueueEvent(events, onEvent, Event(
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
                EnqueueEvent(events, onEvent, Event(
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
                EnqueueEvent(events, onEvent, Event(
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
                EnqueueEvent(events, onEvent, Event(
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
                EnqueueNetworkSession(sessions, onNetworkSession, new NetworkSession(process, "-", "-", data.daddr.ToString(), data.dport, "TCP", DateTimeOffset.Now - startedAt, 0, 0, "-", "-"));
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
                    EnqueueEvent(events, onEvent, Event(
                        Interlocked.Increment(ref nextId),
                        DateTimeOffset.Now - startedAt,
                        KnownProcessName(processNames, pid, null, null),
                        pid,
                        EventCategory.Dns,
                        "DNS Query",
                        query,
                        "DNS event observed by ETW",
                        EventSeverity.Medium,
                        "ETW",
                        data.PayloadString(0)));
                };
            }

            using var durationTimer = options.Duration is null ? null : new Timer(_ => session.Stop(), null, options.Duration.Value, Timeout.InfiniteTimeSpan);
            using var cancellationRegistration = cancellationToken.Register(() => session.Stop());
            session.Source.Process();

            return new EtwCollectionResult(true, true, null, events.OrderBy(e => e.Time).ToArray(), sessions.ToArray());
        }
        catch (Exception ex)
        {
            return new EtwCollectionResult(false, false, ex.Message, events.OrderBy(e => e.Time).ToArray(), sessions.ToArray());
        }
    }

    private static bool PidMatches(int? targetPid, ConcurrentDictionary<int, byte> trackedPids, int observedPid) =>
        !targetPid.HasValue || trackedPids.ContainsKey(observedPid);

    private static void EnqueueEvent(ConcurrentQueue<TimelineEvent> events, Action<TimelineEvent>? onEvent, TimelineEvent timelineEvent)
    {
        events.Enqueue(timelineEvent);
        try
        {
            onEvent?.Invoke(timelineEvent);
        }
        catch
        {
            // UI/live callbacks must not stop the ETW session.
        }
    }

    private static void EnqueueNetworkSession(ConcurrentQueue<NetworkSession> sessions, Action<NetworkSession>? onNetworkSession, NetworkSession session)
    {
        sessions.Enqueue(session);
        try
        {
            onNetworkSession?.Invoke(session);
        }
        catch
        {
            // UI/live callbacks must not stop the ETW session.
        }
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
