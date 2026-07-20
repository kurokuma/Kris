using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed record EtwCollectionResult(
    bool Started,
    bool Completed,
    string? ErrorMessage,
    IReadOnlyList<TimelineEvent> Events,
    IReadOnlyList<NetworkSession> NetworkSessions,
    string? RawTracePath = null,
    long EventsReceived = 0,
    long EventsDropped = 0,
    long NetworkSessionsReceived = 0,
    long NetworkSessionsDropped = 0,
    long RawTraceBytes = 0,
    long RawTraceByteLimit = 0,
    string CaptureLimitReason = "",
    bool TargetBound = false,
    long ScriptContentEventsReceived = 0,
    long ScriptContentEventsDropped = 0,
    long ScriptContentCharactersRetained = 0,
    string ScriptCaptureReason = "",
    string AmsiProviderReason = "",
    string PowerShellProviderReason = "",
    long RegistryEventsReceived = 0,
    long RegistryEventsDropped = 0,
    string RegistryCaptureReason = "",
    long FileEventsReceived = 0,
    long FileEventsDropped = 0,
    string FileCaptureReason = "");
