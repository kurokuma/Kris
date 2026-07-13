namespace MRTW.Core;

/// <summary>Central validation for user/configurable capture limits.</summary>
public static class CaptureLimits
{
    public const int DefaultEvents = 50_000;
    public const int DefaultNetworkSessions = 10_000;
    public const long DefaultRawTraceBytes = 512L * 1024 * 1024;
    public const int MaximumEvents = 500_000;
    public const int MaximumNetworkSessions = 100_000;
    public const long MinimumRawTraceBytes = 1L * 1024 * 1024;
    public const long MaximumRawTraceBytes = 2L * 1024 * 1024 * 1024;

    public static void ValidatePersisted(int events, int networkSessions)
    {
        if (events is < 1 or > MaximumEvents) throw new ArgumentOutOfRangeException(nameof(events), $"Capture event limit must be 1..{MaximumEvents}.");
        if (networkSessions is < 1 or > MaximumNetworkSessions) throw new ArgumentOutOfRangeException(nameof(networkSessions), $"Capture network-session limit must be 1..{MaximumNetworkSessions}.");
    }

    public static void Validate(int events, int networkSessions, long rawTraceBytes)
    {
        ValidatePersisted(events, networkSessions);
        if (rawTraceBytes is < MinimumRawTraceBytes or > MaximumRawTraceBytes)
            throw new ArgumentOutOfRangeException(nameof(rawTraceBytes), $"Raw ETL limit must be {MinimumRawTraceBytes}..{MaximumRawTraceBytes} bytes.");
    }
}
