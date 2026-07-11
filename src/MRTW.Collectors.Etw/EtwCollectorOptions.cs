namespace MRTW.Collectors.Etw;

public sealed record EtwCollectorOptions(
    int? TargetPid,
    TimeSpan? Duration,
    bool ProcessEvents = true,
    bool NetworkEvents = true,
    bool DnsEvents = true,
    bool ImageLoadEvents = true,
    bool FollowDescendants = true,
    DateTimeOffset? CaseStartedAtUtc = null);
