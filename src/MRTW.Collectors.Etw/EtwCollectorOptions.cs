using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed record EtwCollectorOptions(
    int? TargetPid,
    TimeSpan? Duration,
    bool ProcessEvents = true,
    bool NetworkEvents = true,
    bool DnsEvents = true,
    bool ImageLoadEvents = true,
    bool FollowDescendants = true,
    DateTimeOffset? CaseStartedAtUtc = null,
    string? RawTracePath = null,
    int MaxPersistedEvents = CaptureLimits.DefaultEvents,
    int MaxPersistedNetworkSessions = CaptureLimits.DefaultNetworkSessions,
    long MaxRawTraceBytes = CaptureLimits.DefaultRawTraceBytes,
    bool ScriptEvents = true,
    bool RegistryEvents = true,
    bool FileEvents = true,
    int MaxScriptContentEvents = 128,
    int MaxScriptContentCharacters = 131072);
