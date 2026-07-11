using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed record EtwCollectionResult(
    bool Started,
    bool Completed,
    string? ErrorMessage,
    IReadOnlyList<TimelineEvent> Events,
    IReadOnlyList<NetworkSession> NetworkSessions);

