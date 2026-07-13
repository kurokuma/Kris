using System.Collections.Concurrent;
using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed class AnalysisOrchestrator
{
    private readonly RuntimeCaseCollector _runtime = new();

    public CaseData Collect(
        ExecutionProfile profile,
        StaticAnalysisResult? staticAnalysis,
        CancellationToken cancellationToken = default,
        Action<TimelineEvent>? onEvent = null,
        Action<NetworkSession>? onNetworkSession = null)
    {
        return CollectAsync(profile, staticAnalysis, cancellationToken, onEvent, onNetworkSession).GetAwaiter().GetResult();
    }

    public async Task<CaseData> CollectAsync(
        ExecutionProfile profile,
        StaticAnalysisResult? staticAnalysis,
        CancellationToken cancellationToken = default,
        Action<TimelineEvent>? onEvent = null,
        Action<NetworkSession>? onNetworkSession = null)
    {
        var context = CollectionRunContext.Create();
        DateTimeOffset orchestrationStarted = DateTimeOffset.UtcNow;
        using var containment = NetworkContainmentService.Apply(profile);
        var liveEventKeys = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        EtwArmedCapture? armedEtw = null;
        EtwCollectionResult? etw = null;

        void Publish(TimelineEvent item)
        {
            liveEventKeys.TryAdd(EventKey(item), 0);
            onEvent?.Invoke(item);
        }

        DateTimeOffset etwStarted = DateTimeOffset.UtcNow;
        if (profile.EnableEtw && profile.ExecuteTarget && !cancellationToken.IsCancellationRequested)
        {
            TimeSpan? duration = profile.DurationSeconds is int seconds ? TimeSpan.FromSeconds(Math.Max(1, seconds)) : null;
            try
            {
                armedEtw = new TraceEventEtwCollector().Arm(
                    new EtwCollectorOptions(null, duration, FollowDescendants: true, CaseStartedAtUtc: context.StartedAtUtc,
                        RawTracePath: profile.PrivacyMode ? null : Path.Combine(Path.GetTempPath(), "MRTW", context.CaseId, "raw_evidence", "network-process.etl"),
                        MaxPersistedEvents: profile.MaxPersistedEvents, MaxPersistedNetworkSessions: profile.MaxPersistedNetworkSessions),
                    cancellationToken,
                    item => { if (liveEventKeys.TryAdd(EventKey(item), 0)) onEvent?.Invoke(item); },
                    onNetworkSession);
                await armedEtw.Ready.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // ETW is best-effort: a failed ready barrier must not prevent safe runtime collection.
                etw = new EtwCollectionResult(false, false, "ETW pre-launch arm failed: " + ex.Message, [], []);
                armedEtw?.Stop();
                armedEtw?.Dispose();
                armedEtw = null;
            }
        }

        Task<CaseData> runtimeTask = Task.Run(
            () => _runtime.Collect(profile, staticAnalysis, cancellationToken, Publish, context,
                pid => armedEtw?.BindTarget(pid)),
            CancellationToken.None);

        CaseData data = await runtimeTask.ConfigureAwait(false);
        if (armedEtw is not null)
        {
            armedEtw.Stop();
            etw = await armedEtw.Completion.ConfigureAwait(false);
            armedEtw.Dispose();
        }
        DateTimeOffset ended = DateTimeOffset.UtcNow;
        return FinalizeCase(data, etw, profile, containment, orchestrationStarted, etwStarted, ended);
    }

    private static CaseData FinalizeCase(
        CaseData data,
        EtwCollectionResult? etw,
        ExecutionProfile profile,
        NetworkContainmentLease containment,
        DateTimeOffset runtimeStarted,
        DateTimeOffset etwStarted,
        DateTimeOffset ended)
    {
        var combined = data.Events
            .Concat(etw?.Events ?? [])
            .Where(e => e.Category != EventCategory.Behavior)
            .GroupBy(EventKey, StringComparer.Ordinal)
            .Select(g => g.First())
            .OrderBy(e => e.CapturedAtUtc ?? data.StartedAt.Add(e.Time))
            .ThenBy(e => e.Id)
            .Select((e, index) => e with
            {
                Id = index + 1,
                Time = (e.CapturedAtUtc ?? data.StartedAt.Add(e.Time)) - data.StartedAt
            })
            .ToArray();

        var processes = MergeProcessNodes(data, combined);
        combined = AttachProcessGuids(combined, processes, data).ToArray();
        combined = BehaviorCorrelator.Correlate(combined).ToArray();
        var artifacts = BuildArtifacts(combined, processes, data.StartedAt);
        var network = data.NetworkSessions
            .Concat(etw?.NetworkSessions ?? [])
            .GroupBy(n => $"{n.Process}|{n.RemoteIp}|{n.Port}|{n.FirstSeen.TotalMilliseconds:F0}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToArray();

        bool hookRequested = profile.EnableHook;
        bool hookFailed = combined.Any(e => e.Source.Equals("Hook", StringComparison.OrdinalIgnoreCase) &&
            (e.Action.Contains("failed", StringComparison.OrdinalIgnoreCase) || e.Action.Contains("failure", StringComparison.OrdinalIgnoreCase) ||
             e.RawJson.Contains("\"status\":\"failed\"", StringComparison.OrdinalIgnoreCase) ||
             e.RawJson.Contains("\"status\":\"degraded\"", StringComparison.OrdinalIgnoreCase))) ||
            combined.Any(e => e.Action is "Hook Injection Failed" or "Hook Injection Timeout" or "Hook Unavailable");
        bool hookObserved = combined.Any(e => e.Source.Equals("Hook", StringComparison.OrdinalIgnoreCase));
        string hookStatus = !hookRequested ? "disabled" : !profile.ExecuteTarget ? "skipped" : hookFailed ? "degraded" : hookObserved ? "healthy" : "unavailable";
        string etwStatus = !profile.EnableEtw ? "disabled" : !profile.ExecuteTarget ? "skipped" : etw is null ? "unavailable" : !etw.TargetBound ? "degraded" : etw.Started && etw.Completed ? "healthy" : "degraded";
        bool runtimeFailed = combined.Any(e => e.Action is "Execution Failed" or "Live Callback Failures");
        CollectorHealth? runtimeCapture = data.Quality?.Collectors.FirstOrDefault(c => c.Collector == "Runtime");
        CollectorHealth? runtimeNetworkCapture = data.Quality?.Collectors.FirstOrDefault(c => c.Collector == "RuntimeNetwork");
        bool captureBounded = (runtimeCapture?.EventsDropped ?? 0) > 0 || (runtimeNetworkCapture?.EventsDropped ?? 0) > 0 ||
            (etw?.EventsDropped ?? 0) > 0 || (etw?.NetworkSessionsDropped ?? 0) > 0 || !string.IsNullOrWhiteSpace(etw?.CaptureLimitReason);
        var collectors = new List<CollectorHealth>
        {
            new("Runtime", runtimeFailed || (runtimeCapture?.EventsDropped ?? 0) > 0 ? "degraded" : "healthy", runtimeStarted, ended,
                runtimeCapture?.EventsReceived ?? data.Events.Count, runtimeCapture?.EventsDropped ?? 0,
                (runtimeCapture?.Message ?? "") + (runtimeFailed ? " Runtime execution or live delivery reported a failure." : "")),
            new("RuntimeNetwork", (runtimeNetworkCapture?.EventsDropped ?? 0) > 0 ? "degraded" : "healthy", runtimeStarted, ended,
                runtimeNetworkCapture?.EventsReceived ?? data.NetworkSessions.Count, runtimeNetworkCapture?.EventsDropped ?? 0, runtimeNetworkCapture?.Message ?? ""),
            new("Hook", hookStatus, runtimeStarted, ended, combined.Count(e => e.Source.Equals("Hook", StringComparison.OrdinalIgnoreCase)), combined.Count(e => e.Action == "Hook Parse Failure"),
                hookFailed ? "One or more hook adapters or injection operations failed." : ""),
            new("ETW", captureBounded && (!string.IsNullOrWhiteSpace(etw?.CaptureLimitReason) || (etw?.EventsDropped ?? 0) > 0) ? "degraded" : etwStatus,
                etwStarted, ended, etw?.EventsReceived ?? 0, etw?.EventsDropped ?? 0,
                (etw?.ErrorMessage ?? "") + " " + (etw?.CaptureLimitReason ?? "") + (etw is { TargetBound: false } ? " Target PID was never bound; no structured ETW data was retained." : "") + $" event_limit={profile.MaxPersistedEvents};network_limit={profile.MaxPersistedNetworkSessions};raw_etl_limit={(etw?.RawTraceByteLimit ?? 0)}. Raw kernel ETL is system-wide before PID bind; persisted structured events, callbacks, and network sessions are discarded until the target PID tree is bound.")
            ,new("ETWNetwork", (etw?.NetworkSessionsDropped ?? 0) > 0 || !string.IsNullOrWhiteSpace(etw?.CaptureLimitReason) ? "degraded" : etwStatus,
                etwStarted, ended, etw?.NetworkSessionsReceived ?? 0, etw?.NetworkSessionsDropped ?? 0,
                (etw?.CaptureLimitReason ?? "") + $" network_limit={profile.MaxPersistedNetworkSessions};network_received={(etw?.NetworkSessionsReceived ?? 0)};network_dropped={(etw?.NetworkSessionsDropped ?? 0)}.")
        };
        string overall = captureBounded || collectors.Any(c => c.Status == "degraded" || c.Status == "unavailable" && c.Collector != "Hook")
            ? "degraded"
            : "healthy";

        return data with
        {
            Events = combined,
            Processes = processes,
            Artifacts = artifacts,
            NetworkSessions = network,
            Duration = ended - data.StartedAt,
            AnalystNotes = data.AnalystNotes + $" Collection quality: {overall}. Network containment: {containment.Message} Evidence staging uses the current Windows token; export rehash rejects detected temporary-evidence changes but does not provide cross-token tamper-proof storage.",
            Quality = new CaseQuality(overall, collectors, containment.Message, true),
            RawEvidenceFiles = etw?.RawTracePath is string raw && File.Exists(raw) ? [raw] : data.RawEvidenceFiles,
            RawEvidence = BuildRawEvidence(etw)
        };
    }

    private static IReadOnlyList<RawEvidenceFile> BuildRawEvidence(EtwCollectionResult? etw)
    {
        if (etw?.RawTracePath is not string path || !File.Exists(path)) return [];
        try { using var stream = File.OpenRead(path); return [new(path, stream.Length, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant(), "system-wide kernel ETL; structured events are target PID-tree filtered")]; }
        catch { return []; }
    }

    private static IReadOnlyList<ProcessNode> MergeProcessNodes(CaseData data, IReadOnlyList<TimelineEvent> events)
    {
        var nodes = data.Processes.ToDictionary(p => p.Pid, p => p);
        foreach (var group in events.Where(e => e.Pid > 0).GroupBy(e => e.Pid))
        {
            if (nodes.ContainsKey(group.Key))
            {
                ProcessNode old = nodes[group.Key];
                nodes[group.Key] = old with
                {
                    EventCount = group.Count(),
                    NetworkCount = group.Count(e => e.Category == EventCategory.Network),
                    FileCount = group.Count(e => e.Category == EventCategory.File),
                    RegistryCount = group.Count(e => e.Category == EventCategory.Registry)
                };
                continue;
            }
            TimelineEvent first = group.OrderBy(e => e.Time).First();
            DateTimeOffset start = first.CapturedAtUtc ?? data.StartedAt.Add(first.Time);
            nodes[group.Key] = new ProcessNode(first.Process, group.Key, null,
                $"{data.CaseId}:{group.Key}:{start.UtcTicks}", "", "", start, null,
                group.Count(), group.Count(e => e.Category == EventCategory.Network),
                group.Count(e => e.Category == EventCategory.File), group.Count(e => e.Category == EventCategory.Registry));
        }
        return nodes.Values.OrderBy(p => p.StartTime).ToArray();
    }

    private static IEnumerable<TimelineEvent> AttachProcessGuids(IEnumerable<TimelineEvent> events, IReadOnlyList<ProcessNode> processes, CaseData data)
    {
        var byPid = processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First().ProcessGuid);
        foreach (TimelineEvent item in events)
        {
            yield return string.IsNullOrWhiteSpace(item.ProcessGuid) && byPid.TryGetValue(item.Pid, out string? guid)
                ? item with { ProcessGuid = guid }
                : item;
        }
    }

    private static IReadOnlyList<ArtifactItem> BuildArtifacts(IReadOnlyList<TimelineEvent> events, IReadOnlyList<ProcessNode> processes, DateTimeOffset started)
    {
        return events
            .Where(e => e.Category is EventCategory.File or EventCategory.Registry or EventCategory.Network or EventCategory.Dns or EventCategory.Api)
            .GroupBy(e => e.Category)
            .Select(g => new ArtifactItem(g.Key.ToString(),
                string.Join(", ", g.Select(e => e.ObjectValue).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(12)),
                started.Add(g.Min(e => e.Time)), started.Add(g.Max(e => e.Time)), g.Count(),
                string.Join(", ", g.Select(e => e.Process).Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
                g.Any(e => e.Severity is EventSeverity.Critical or EventSeverity.High) ? EventSeverity.High :
                    g.Any(e => e.Severity == EventSeverity.Medium) ? EventSeverity.Medium : EventSeverity.Low))
            .OrderByDescending(a => a.EventCount)
            .ToArray();
    }

    private static string EventKey(TimelineEvent e) =>
        $"{e.Source}|{e.Pid}|{e.Action}|{e.ObjectValue}|{(e.CapturedAtUtc ?? DateTimeOffset.MinValue).UtcTicks}";
}
