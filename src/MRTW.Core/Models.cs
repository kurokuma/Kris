using System.Text.Json.Serialization;

namespace MRTW.Core;

public enum EventCategory
{
    Process,
    Api,
    File,
    Registry,
    Dns,
    Network,
    Module,
    Credential,
    Service,
    Task,
    Snapshot,
    Behavior
}

public enum EventSeverity
{
    Critical,
    High,
    Medium,
    Low,
    Informational,
    Hidden
}

public sealed record ProcessNode(
    string Name,
    int Pid,
    int? ParentPid,
    string ProcessGuid,
    string CommandLine,
    string ImagePath,
    DateTimeOffset StartTime,
    DateTimeOffset? EndTime,
    int EventCount,
    int NetworkCount,
    int FileCount,
    int RegistryCount);

public sealed record TimelineEvent(
    int Id,
    TimeSpan Time,
    string Process,
    int Pid,
    EventCategory Category,
    string Action,
    string ObjectValue,
    string Summary,
    EventSeverity Severity,
    string Source,
    string RawJson,
    string TechniqueId = "",
    string TechniqueName = "",
    string Confidence = "",
    string ProcessGuid = "",
    DateTimeOffset? CapturedAtUtc = null);

public sealed record CollectorHealth(
    string Collector,
    string Status,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset EndedAtUtc,
    long EventsReceived,
    long EventsDropped,
    string Message = "");

public sealed record CaseQuality(
    string OverallStatus,
    IReadOnlyList<CollectorHealth> Collectors,
    string NetworkContainment,
    bool ProcessTreeFollowed,
    string ClockSource = "UTC+Stopwatch");

public sealed record ArtifactItem(
    string Type,
    string Value,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    int EventCount,
    string RelatedProcesses,
    EventSeverity Severity);

public sealed record NetworkSession(
    string Process,
    string Domain,
    string ResolvedIp,
    string RemoteIp,
    int Port,
    string Protocol,
    TimeSpan FirstSeen,
    long BytesSent,
    long BytesReceived,
    string UserAgent,
    string Sni,
    string DnsStatus = "",
    string DnsAnswers = "",
    string Coverage = "metadata-only",
    string HttpMethod = "",
    string HttpHost = "",
    string HttpUri = "",
    string HttpHeaders = "");

public sealed record PeSectionInfo(string Name, uint VirtualAddress, uint RawSize, double Entropy, uint VirtualSize = 0, string Characteristics = "");

public sealed record EmbeddedPeInfo(long Offset, string Architecture, string Sha256, long Size);
public sealed record PreservedFile(string OriginalPath, string StoredPath, long Size, string Sha256, string Reason);
public sealed record RawEvidenceFile(string StoredPath, long Size, string Sha256, string Coverage);

public sealed record StaticAnalysisResult(
    string FileName,
    string FullPath,
    long FileSize,
    string Md5,
    string Sha1,
    string Sha256,
    string FileType,
    string Architecture,
    DateTimeOffset? PeTimestamp,
    string EntryPoint,
    IReadOnlyList<string> Imports,
    IReadOnlyList<string> Exports,
    IReadOnlyList<PeSectionInfo> Sections,
    IReadOnlyList<string> SuspiciousStrings,
    bool IsDotNet,
    bool HasDigitalSignature,
    long OverlaySize,
    string Subsystem = "",
    ulong ImageBase = 0,
    IReadOnlyList<string>? Resources = null,
    IReadOnlyList<string>? TlsCallbacks = null,
    string PdbPath = "",
    string SignatureStatus = "Not signed",
    string SignatureSubject = "",
    string Imphash = "",
    string RichHeaderHash = "",
    string Manifest = "",
    IReadOnlyDictionary<string, string>? VersionInfo = null,
    IReadOnlyList<string>? DotNetMetadata = null,
    IReadOnlyList<string>? PackerIndicators = null,
    IReadOnlyList<EmbeddedPeInfo>? EmbeddedPeFiles = null,
    NonPeTriageResult? NonPeTriage = null);

/// <summary>Read-only, bounded first-look findings for a non-PE target.  No finding is executed or resolved.</summary>
public sealed record NonPeTriageResult(
    string Format,
    bool CanExecute,
    IReadOnlyList<string> Indicators,
    IReadOnlyList<string> UrlCandidates,
    IReadOnlyList<string> CommandCandidates,
    IReadOnlyList<string> EncodedContentMarkers,
    IReadOnlyList<string> ContainerEntries,
    IReadOnlyList<string> SafetyWarnings);

/// <summary>Read-only bounded command normalization evidence. Decoded text is never executed.</summary>
public sealed record NormalizedCommand(
    string Original,
    string Normalized,
    string Decoder,
    string Status,
    string FailureReason = "",
    string LolBin = "",
    string ProcessGuid = "",
    int? Pid = null,
    TimeSpan? Time = null,
    IReadOnlyList<int>? EvidenceEventIds = null);

public sealed record CaseData(
    string CaseId,
    string CaseName,
    string SampleName,
    string SamplePath,
    string Sha256,
    DateTimeOffset StartedAt,
    TimeSpan Duration,
    StaticAnalysisResult? StaticAnalysis,
    IReadOnlyList<ProcessNode> Processes,
    IReadOnlyList<TimelineEvent> Events,
    IReadOnlyList<ArtifactItem> Artifacts,
    IReadOnlyList<NetworkSession> NetworkSessions,
    string AnalystNotes,
    CaseQuality? Quality = null,
    IReadOnlyList<string>? RawEvidenceFiles = null,
    IReadOnlyList<PreservedFile>? PreservedFiles = null)
{
    [JsonIgnore]
    public string TrustedEvidenceRoot { get; init; } = "";
    public IReadOnlyList<RawEvidenceFile> RawEvidence { get; init; } = [];
    // Appended for JSON/SQLite backward compatibility with existing case bundles.
    public IReadOnlyList<NormalizedCommand> NormalizedCommands { get; init; } = [];
    [JsonIgnore]
    public int HighCount => Events.Count(e => e.Severity is EventSeverity.Critical or EventSeverity.High);

    [JsonIgnore]
    public int MediumCount => Events.Count(e => e.Severity == EventSeverity.Medium);
}

public sealed record ExportOptions(
    string Formats,
    bool PrivacyMode = false,
    bool IncludeSample = false,
    bool IncludeRaw = true,
    bool Compress = true);

public sealed record MrtwConfig(
    string Workspace,
    string Exports,
    string DefaultProfile,
    IReadOnlyDictionary<string, ProfileDefaults> Profiles,
    string LogFormat = "text",
    bool Quiet = false,
    bool Verbose = false)
{
    public static MrtwConfig Default { get; } = new(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MRTW", "Workspace"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MRTW", "Exports"),
        "full-capture",
        new Dictionary<string, ProfileDefaults>(StringComparer.OrdinalIgnoreCase)
        {
            ["quick"] = new(30, true, false, true, true, true, "html,jsonl,sqlite", "observe", "kill", true),
            ["full-capture"] = new(120, true, true, true, true, true, "all", "observe", "kill", true)
        });
}

public sealed record ProfileDefaults(
    int Duration,
    bool Etw,
    bool Hook,
    bool SnapshotBefore,
    bool SnapshotAfter,
    bool Static,
    string Format,
    string Network,
    string TimeoutAction,
    bool KillTree);

public sealed record FileSnapshotEntry(string Path, long Size, DateTimeOffset LastWriteUtc, string Sha256 = "", string Attributes = "", DateTimeOffset? CreatedUtc = null, bool IsExecutable = false, bool TimestampAnomaly = false, IReadOnlyList<string>? AlternateStreams = null);

public sealed record RegistrySnapshotEntry(string KeyPath, string Name, string Value);

/// <summary>Read-only, normalized representation of an autostart mechanism.</summary>
public sealed record PersistenceSnapshotEntry(
    string Surface,
    string Identity,
    string DisplayName,
    string ExecutionTarget,
    string Fingerprint);

public sealed record SnapshotData(
    DateTimeOffset CapturedAt,
    IReadOnlyList<FileSnapshotEntry> Files,
    IReadOnlyList<RegistrySnapshotEntry> RegistryValues,
    IReadOnlyList<string> TcpConnections,
    IReadOnlyList<PersistenceSnapshotEntry>? PersistenceEntries = null,
    IReadOnlyList<CollectorHealth>? PersistenceQuality = null);

/// <summary>Bounded snapshot result used by interactive collection.</summary>
public sealed record SnapshotCaptureResult(SnapshotData Data, bool Completed, bool Canceled, bool Bounded, string Note);

public sealed record SnapshotDiff(
    IReadOnlyList<FileSnapshotEntry> AddedFiles,
    IReadOnlyList<FileSnapshotEntry> ModifiedFiles,
    IReadOnlyList<string> DeletedFiles,
    IReadOnlyList<RegistrySnapshotEntry> AddedRegistryValues,
    IReadOnlyList<RegistrySnapshotEntry> ModifiedRegistryValues,
    IReadOnlyList<string> DeletedRegistryValues,
    IReadOnlyList<string> NewTcpConnections,
    IReadOnlyList<PersistenceSnapshotEntry>? AddedPersistenceEntries = null,
    IReadOnlyList<PersistenceSnapshotEntry>? ModifiedPersistenceEntries = null,
    IReadOnlyList<PersistenceSnapshotEntry>? DeletedPersistenceEntries = null);

public sealed record ExecutionProfile(
    string TargetPath,
    string TargetType,
    string Runner,
    string? ExportFunction,
    string CommandLine,
    string WorkingDirectory,
    int? DurationSeconds,
    bool EnableEtw,
    bool EnableHook,
    bool SnapshotBefore,
    bool SnapshotAfter,
    string NetworkMode,
    bool KillTree = true,
    string TimeoutAction = "kill",
    bool ExecuteTarget = true,
    bool PrivacyMode = false,
    int MaxPersistedEvents = CaptureLimits.DefaultEvents,
    int MaxPersistedNetworkSessions = CaptureLimits.DefaultNetworkSessions);

public sealed record CollectionRunContext(string CaseId, DateTimeOffset StartedAtUtc)
{
    public static CollectionRunContext Create()
    {
        CleanupExpiredEvidence();
        return new("case-" + Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow);
    }
    private static void CleanupExpiredEvidence()
    {
        string root = Path.Combine(Path.GetTempPath(), "MRTW");
        try
        {
            foreach (string directory in Directory.EnumerateDirectories(root, "case-*", SearchOption.TopDirectoryOnly).Take(200))
            {
                var info = new DirectoryInfo(directory);
                if ((info.Attributes & FileAttributes.ReparsePoint) == 0 && info.LastWriteTimeUtc < DateTime.UtcNow.AddHours(-24)) Directory.Delete(directory, true);
            }
        }
        catch { }
    }
}
