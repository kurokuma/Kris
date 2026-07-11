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
    string ProcessGuid = "");

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
    string Sni);

public sealed record PeSectionInfo(string Name, uint VirtualAddress, uint RawSize, double Entropy);

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
    string PdbPath = "");

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
    string AnalystNotes)
{
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

public sealed record FileSnapshotEntry(string Path, long Size, DateTimeOffset LastWriteUtc);

public sealed record RegistrySnapshotEntry(string KeyPath, string Name, string Value);

public sealed record SnapshotData(
    DateTimeOffset CapturedAt,
    IReadOnlyList<FileSnapshotEntry> Files,
    IReadOnlyList<RegistrySnapshotEntry> RegistryValues,
    IReadOnlyList<string> TcpConnections);

public sealed record SnapshotDiff(
    IReadOnlyList<FileSnapshotEntry> AddedFiles,
    IReadOnlyList<FileSnapshotEntry> ModifiedFiles,
    IReadOnlyList<string> DeletedFiles,
    IReadOnlyList<RegistrySnapshotEntry> AddedRegistryValues,
    IReadOnlyList<RegistrySnapshotEntry> ModifiedRegistryValues,
    IReadOnlyList<string> DeletedRegistryValues,
    IReadOnlyList<string> NewTcpConnections);

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
    bool ExecuteTarget = true);
