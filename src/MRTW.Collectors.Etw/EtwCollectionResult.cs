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
    string CaptureLimitReason = "");
