using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using MRTW.Core;

namespace MRTW.App;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private TimelineEvent? _selectedEvent;
    private string _samplePath = string.Empty;
    private bool _isMonitoring = true;
    private string _statusText = "Ready";
    private ProfileOption _selectedProfile;
    private string _runDuration = "00:00:00";
    private ExportSettings _exportSettings = new();
    private string _timelineSearchText = string.Empty;
    private string _selectedTimeRange = "All Time";
    private string _selectedProcessFilter = "All Processes";
    private string _selectedDllExport = "DllRegisterServer";
    private bool _showProcessEvents = true;
    private bool _showFileEvents = true;
    private bool _showRegistryEvents = true;
    private bool _showNetworkEvents = true;
    private bool _showDnsEvents = true;
    private bool _showApiEvents = true;
    private bool _showBehaviorEvents = true;
    private bool _showNoiseEvents;
    private ProcessNode? _selectedProcessNode;
    private readonly Stopwatch _runClock = new();

    public MainViewModel()
    {
        Profiles =
        [
            new("default", "Default", 60, true, false, true, true, "observe", "kill", "Uses the configured default intent with balanced runtime collection. In the GUI, runtime collection continues until the target exits or Stop is pressed."),
            new("quick", "Quick", 30, true, false, true, true, "observe", "kill", "Fast first-look profile. In the GUI, it captures static metadata, snapshots, ETW, and runtime events until the target exits or Stop is pressed."),
            new("full-capture", "Full Capture", 120, true, true, true, true, "observe", "kill", "Deeper profile with native hook capture enabled when available. In the GUI, runtime collection has no fixed time limit.")
        ];
        _selectedProfile = Profiles[0];
        StaticAnalysis = EmptyStaticAnalysis();
        CurrentCase = EmptyCase();
        SelectedEvent = null;
        LoadRecentCases();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public CaseData CurrentCase { get; private set; }

    public StaticAnalysisResult StaticAnalysis { get; private set; }

    public ObservableCollection<CaseListItem> RecentCases { get; } = [];

    public ObservableCollection<ProfileOption> Profiles { get; }

    public ProfileOption SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            _selectedProfile = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(AnalysisSummary));
            OnPropertyChanged(nameof(AnalysisLimitText));
        }
    }

    public TimelineEvent? SelectedEvent
    {
        get => _selectedEvent;
        set
        {
            _selectedEvent = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(RelatedEvidenceEvents));
            OnPropertyChanged(nameof(EvidenceSummary));
        }
    }

    public string SamplePath
    {
        get => _samplePath;
        set
        {
            _samplePath = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(SelectedTargetDisplay));
            OnPropertyChanged(nameof(AnalysisSummary));
        }
    }

    public string SelectedTargetDisplay => string.IsNullOrWhiteSpace(SamplePath) ? "No target selected" : Path.GetFileName(SamplePath);

    public string AnalysisLimitText => "No limit";

    public bool IsMonitoring
    {
        get => _isMonitoring;
        set
        {
            _isMonitoring = value;
            OnPropertyChanged();
        }
    }

    public string StatusText
    {
        get => _statusText;
        set
        {
            _statusText = value;
            OnPropertyChanged();
        }
    }

    public string RunDuration
    {
        get => _runDuration;
        private set
        {
            _runDuration = value;
            OnPropertyChanged();
        }
    }

    public string AnalysisSummary
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SamplePath) && CurrentCase.Events.Count == 0)
            {
                return "Open a target from File > Open Target, then use Start to execute the selected file under the active profile.";
            }

            return $"{CurrentCase.Events.Count} timeline events, {CurrentCase.Processes.Count} process nodes, {CurrentCase.Artifacts.Count} artifact groups, and {CurrentCase.NetworkSessions.Count} network sessions are loaded for the current analysis.";
        }
    }

    public string CollectionQualityStatus => CurrentCase.Quality?.OverallStatus ?? "not recorded";

    public string CollectionQualitySummary => CurrentCase.Quality is null
        ? "Collector health metadata is not available for this case."
        : string.Join(" | ", CurrentCase.Quality.Collectors.Select(c =>
            $"{c.Collector}: {c.Status} ({c.EventsReceived} events, {c.EventsDropped} dropped)")) +
          $" | Network: {CurrentCase.Quality.NetworkContainment}";

    public ExportSettings ExportSettings
    {
        get => _exportSettings;
        set
        {
            _exportSettings = value;
            OnPropertyChanged();
        }
    }

    public IReadOnlyList<string> TimeRangeOptions { get; } =
    [
        "All Time",
        "Last 1 Minute",
        "Last 5 Minutes",
        "Last 15 Minutes"
    ];

    public IReadOnlyList<string> ProcessFilterOptions =>
        new[] { "All Processes" }
            .Concat(CurrentCase.Events.Select(e => e.Process).Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
            .ToArray();

    public IReadOnlyList<TimelineEvent> FilteredEvents => ApplyTimelineFilters();

    public IReadOnlyList<string> DllExportCandidates
    {
        get
        {
            var candidates = StaticAnalysis.Exports
                .Where(e => !string.IsNullOrWhiteSpace(e))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (candidates.Count == 0)
            {
                candidates.Add("DllRegisterServer");
            }

            return candidates;
        }
    }

    public string SelectedDllExport
    {
        get => _selectedDllExport;
        set
        {
            _selectedDllExport = string.IsNullOrWhiteSpace(value) ? "DllRegisterServer" : value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(AnalysisSummary));
        }
    }

    public string TimelineSearchText
    {
        get => _timelineSearchText;
        set
        {
            _timelineSearchText = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public string SelectedTimeRange
    {
        get => _selectedTimeRange;
        set
        {
            _selectedTimeRange = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public string SelectedProcessFilter
    {
        get => _selectedProcessFilter;
        set
        {
            _selectedProcessFilter = value;
            if (!string.Equals(value, "All Processes", StringComparison.OrdinalIgnoreCase))
            {
                _selectedProcessNode = null;
                OnPropertyChanged(nameof(SelectedProcessNode));
                OnPropertyChanged(nameof(ProcessTreeFilterSummary));
            }

            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowProcessEvents
    {
        get => _showProcessEvents;
        set
        {
            _showProcessEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowFileEvents
    {
        get => _showFileEvents;
        set
        {
            _showFileEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowRegistryEvents
    {
        get => _showRegistryEvents;
        set
        {
            _showRegistryEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowNetworkEvents
    {
        get => _showNetworkEvents;
        set
        {
            _showNetworkEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowDnsEvents
    {
        get => _showDnsEvents;
        set
        {
            _showDnsEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowApiEvents
    {
        get => _showApiEvents;
        set
        {
            _showApiEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowBehaviorEvents
    {
        get => _showBehaviorEvents;
        set
        {
            _showBehaviorEvents = value;
            OnPropertyChanged();
            OnTimelineFilterChanged();
        }
    }

    public bool ShowNoiseEvents
    {
        get => _showNoiseEvents;
        set
        {
            _showNoiseEvents = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(NoiseSummary));
            OnTimelineFilterChanged();
        }
    }

    public ProcessNode? SelectedProcessNode
    {
        get => _selectedProcessNode;
        set
        {
            _selectedProcessNode = value;
            if (value is not null)
            {
                _selectedProcessFilter = "All Processes";
                OnPropertyChanged(nameof(SelectedProcessFilter));
            }

            OnPropertyChanged();
            OnPropertyChanged(nameof(ProcessTreeFilterSummary));
            OnTimelineFilterChanged();
        }
    }

    public int FileEventCount => CurrentCase.Events.Count(e => e.Category == EventCategory.File);
    public int RegistryEventCount => CurrentCase.Events.Count(e => e.Category == EventCategory.Registry);
    public int NetworkEventCount => CurrentCase.Events.Count(e => e.Category == EventCategory.Network);
    public int DnsEventCount => CurrentCase.Events.Count(e => e.Category == EventCategory.Dns);
    public int NoiseEventCount => CurrentCase.Events.Count(IsNoisyEvent);
    public string NoiseSummary => ShowNoiseEvents ? "Noisy API events are visible" : $"{NoiseEventCount} noisy events hidden";
    public string ProcessTreeFilterSummary => SelectedProcessNode is null ? "No process tree filter" : $"Filtered by {SelectedProcessNode.Name} (PID {SelectedProcessNode.Pid})";
    public IReadOnlyList<ArtifactItem> FileArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.File), "File");
    public IReadOnlyList<ArtifactItem> RegistryArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Registry), "Registry");
    public IReadOnlyList<ArtifactItem> ProcessArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Process), "Process");
    public IReadOnlyList<ArtifactItem> CommandArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Process && ContainsAny(e.RawJson + " " + e.ObjectValue + " " + e.Summary, "cmd.exe", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32")), "Command");
    public IReadOnlyList<ArtifactItem> NetworkArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Network), "Network");
    public IReadOnlyList<ArtifactItem> DnsArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Dns), "DNS");
    public IReadOnlyList<ArtifactItem> ModuleArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Module), "Module");
    public IReadOnlyList<ArtifactItem> CredentialApiArtifacts => BuildArtifactItems(CurrentCase.Events.Where(e => e.Category == EventCategory.Credential || ContainsAny(e.Action, "Cred", "CryptUnprotectData", "MiniDumpWriteDump")), "Credential API");
    public IReadOnlyList<TimelineEvent> RelatedEvidenceEvents => GetRelatedEvidenceEvents();
    public string EvidenceSummary => SelectedEvent?.Category == EventCategory.Behavior
        ? RelatedEvidenceEvents.Count == 0 ? "No evidence IDs were recorded for this behavior event." : $"{RelatedEvidenceEvents.Count} evidence events support this behavior."
        : "Select a Behavior event to inspect its supporting evidence.";

    public void SelectTarget(string path)
    {
        SamplePath = path;
        StaticAnalysis = File.Exists(path) ? new StaticAnalysisService().Analyze(path) : StaticAnalysis;
        SelectedDllExport = DllExportCandidates.FirstOrDefault(e => e.Equals("DllRegisterServer", StringComparison.OrdinalIgnoreCase))
            ?? DllExportCandidates.FirstOrDefault()
            ?? "DllRegisterServer";
        CurrentCase = EmptyCase() with
        {
            SampleName = Path.GetFileName(path),
            SamplePath = path,
            StaticAnalysis = StaticAnalysis
        };
        SelectedEvent = null;
        StatusText = "Target selected";
        ResetRunDuration();
        RefreshCaseBindings();
    }

    public ExecutionProfile PrepareRun()
    {
        if (string.IsNullOrWhiteSpace(SamplePath))
        {
            throw new InvalidOperationException("No target file is selected.");
        }

        StatusText = "Running";
        IsMonitoring = true;
        ResetRunDuration();
        _runClock.Restart();
        return BuildExecutionProfile(SamplePath);
    }

    public void BeginLiveRun(ExecutionProfile profile)
    {
        CurrentCase = new CaseData(
            "case-live",
            $"{Path.GetFileNameWithoutExtension(profile.TargetPath)}_running",
            Path.GetFileName(profile.TargetPath),
            profile.TargetPath,
            StaticAnalysis.Sha256,
            DateTimeOffset.Now,
            TimeSpan.Zero,
            StaticAnalysis,
            Array.Empty<ProcessNode>(),
            Array.Empty<TimelineEvent>(),
            Array.Empty<ArtifactItem>(),
            Array.Empty<NetworkSession>(),
            "Analysis is running. Timeline events are appended as they are captured.");
        SelectedEvent = null;
        RefreshCaseBindings();
    }

    public void AppendLiveEvent(TimelineEvent timelineEvent)
    {
        var events = BehaviorCorrelator.Correlate(CurrentCase.Events.Concat([timelineEvent]).OrderBy(e => e.Time).ToArray()).ToArray();
        var processNodes = BuildLiveProcessNodes(events);
        events = AttachLiveProcessGuids(events, processNodes, CurrentCase.CaseId, CurrentCase.StartedAt);
        CurrentCase = CurrentCase with
        {
            Duration = _runClock.Elapsed,
            Events = events,
            Processes = processNodes,
            Artifacts = BuildLiveArtifacts(events, processNodes),
            AnalystNotes = "Analysis is running. Timeline events are appended as they are captured."
        };

        SelectedEvent ??= timelineEvent;
        RefreshCaseBindings();
    }

    public void AppendLiveNetworkSession(NetworkSession session)
    {
        CurrentCase = CurrentCase with
        {
            Duration = _runClock.Elapsed,
            NetworkSessions = CurrentCase.NetworkSessions.Concat([session]).ToArray(),
            AnalystNotes = "Analysis is running. Timeline events are appended as they are captured."
        };

        RefreshCaseBindings();
    }

    public void CompleteRun(CaseData data, bool stopped)
    {
        var events = BehaviorCorrelator.Correlate(data.Events).ToArray();
        CurrentCase = data with { Events = events, Artifacts = BuildLiveArtifacts(events, data.Processes) };
        StatusText = stopped ? "Stopped" : "Analysis completed";
        SelectedEvent = CurrentCase.Events.FirstOrDefault();
        IsMonitoring = false;
        _runClock.Stop();
        UpdateRunDuration();
        RefreshCaseBindings();
    }

    public void FailRun(string message)
    {
        StatusText = message;
        IsMonitoring = false;
        _runClock.Stop();
        UpdateRunDuration();
        OnPropertyChanged(nameof(AnalysisSummary));
        OnPropertyChanged(nameof(CollectionQualityStatus));
        OnPropertyChanged(nameof(CollectionQualitySummary));
    }

    public void MarkStopping()
    {
        StatusText = "Stopping";
    }

    public void UpdateRunDuration()
    {
        RunDuration = _runClock.Elapsed.ToString(@"hh\:mm\:ss");
    }

    private void ResetRunDuration()
    {
        _runClock.Reset();
        RunDuration = "00:00:00";
    }

    private ExecutionProfile BuildExecutionProfile(string path)
    {
        var selected = SelectedProfile;
        var config = new MrtwConfigService().Load();
        if (selected.Id.Equals("default", StringComparison.OrdinalIgnoreCase))
        {
            selected = ResolveConfiguredDefault(config);
        }

        string extension = Path.GetExtension(path);
        bool isDll = extension.Equals(".dll", StringComparison.OrdinalIgnoreCase);
        var profile = new ExecutionProfile(
            path,
            isDll ? "dll" : "exe",
            isDll ? "rundll32" : "none",
            isDll ? SelectedDllExport : null,
            $"\"{path}\"",
            Path.GetDirectoryName(path) ?? Environment.CurrentDirectory,
            null,
            selected.EnableEtw,
            selected.EnableHook,
            selected.SnapshotBefore,
            selected.SnapshotAfter,
            selected.NetworkMode,
            true,
            selected.TimeoutAction,
            true,
            PrivacyMode);
        return profile;
    }

    public bool PrivacyMode { get; set; }

    private static ProfileOption ResolveConfiguredDefault(MrtwConfig config)
    {
        if (config.Profiles.TryGetValue(config.DefaultProfile, out var defaults))
        {
            return new ProfileOption(
                config.DefaultProfile,
                ToDisplayName(config.DefaultProfile),
                defaults.Duration,
                defaults.Etw,
                defaults.Hook,
                defaults.SnapshotBefore,
                defaults.SnapshotAfter,
                defaults.Network,
                defaults.TimeoutAction,
                $"Configured default profile from config.yaml. GUI runs without a fixed time limit; CLI/config duration is {defaults.Duration} seconds. ETW {(defaults.Etw ? "on" : "off")}, hook {(defaults.Hook ? "on" : "off")}.");
        }

        return new ProfileOption("full-capture", "Full Capture", 120, true, true, true, true, "observe", "kill", "Fallback default full runtime profile.");
    }

    public void LoadCase(string casePath)
    {
        CurrentCase = new CaseService().Load(casePath);
        StaticAnalysis = CurrentCase.StaticAnalysis ?? EmptyStaticAnalysis();
        SamplePath = CurrentCase.SamplePath;
        SelectedEvent = CurrentCase.Events.FirstOrDefault();
        StatusText = "Case opened";
        ResetRunDuration();
        RefreshCaseBindings();
    }

    public string ExportCurrentCase(string outputRoot, bool privacyMode = false)
    {
        string caseDir = Path.Combine(outputRoot, CurrentCase.CaseName);
        new CaseExportService().WriteCaseBundle(CurrentCase, caseDir, ExportSettings.ToExportOptions(privacyMode));
        StatusText = "Case exported";
        return caseDir;
    }

    private void RefreshCaseBindings()
    {
        OnPropertyChanged(nameof(CurrentCase));
        OnPropertyChanged(nameof(FilteredEvents));
        OnPropertyChanged(nameof(ProcessFilterOptions));
        OnPropertyChanged(nameof(StaticAnalysis));
        OnPropertyChanged(nameof(DllExportCandidates));
        OnPropertyChanged(nameof(SelectedDllExport));
        OnPropertyChanged(nameof(FileEventCount));
        OnPropertyChanged(nameof(RegistryEventCount));
        OnPropertyChanged(nameof(NetworkEventCount));
        OnPropertyChanged(nameof(DnsEventCount));
        OnPropertyChanged(nameof(NoiseEventCount));
        OnPropertyChanged(nameof(NoiseSummary));
        OnPropertyChanged(nameof(ProcessTreeFilterSummary));
        OnPropertyChanged(nameof(FileArtifacts));
        OnPropertyChanged(nameof(RegistryArtifacts));
        OnPropertyChanged(nameof(ProcessArtifacts));
        OnPropertyChanged(nameof(CommandArtifacts));
        OnPropertyChanged(nameof(NetworkArtifacts));
        OnPropertyChanged(nameof(DnsArtifacts));
        OnPropertyChanged(nameof(ModuleArtifacts));
        OnPropertyChanged(nameof(CredentialApiArtifacts));
        OnPropertyChanged(nameof(RelatedEvidenceEvents));
        OnPropertyChanged(nameof(EvidenceSummary));
        OnPropertyChanged(nameof(AnalysisSummary));
        OnPropertyChanged(nameof(SelectedTargetDisplay));
    }

    public void ResetTimelineFilters()
    {
        _timelineSearchText = string.Empty;
        _selectedTimeRange = "All Time";
        _selectedProcessFilter = "All Processes";
        _showProcessEvents = true;
        _showFileEvents = true;
        _showRegistryEvents = true;
        _showNetworkEvents = true;
        _showDnsEvents = true;
        _showApiEvents = true;
        _showBehaviorEvents = true;
        _showNoiseEvents = false;
        _selectedProcessNode = null;
        OnPropertyChanged(nameof(TimelineSearchText));
        OnPropertyChanged(nameof(SelectedTimeRange));
        OnPropertyChanged(nameof(SelectedProcessFilter));
        OnPropertyChanged(nameof(ShowProcessEvents));
        OnPropertyChanged(nameof(ShowFileEvents));
        OnPropertyChanged(nameof(ShowRegistryEvents));
        OnPropertyChanged(nameof(ShowNetworkEvents));
        OnPropertyChanged(nameof(ShowDnsEvents));
        OnPropertyChanged(nameof(ShowApiEvents));
        OnPropertyChanged(nameof(ShowBehaviorEvents));
        OnPropertyChanged(nameof(ShowNoiseEvents));
        OnPropertyChanged(nameof(SelectedProcessNode));
        OnPropertyChanged(nameof(NoiseSummary));
        OnPropertyChanged(nameof(ProcessTreeFilterSummary));
        OnTimelineFilterChanged();
    }

    private void OnTimelineFilterChanged()
    {
        OnPropertyChanged(nameof(FilteredEvents));
    }

    private IReadOnlyList<TimelineEvent> ApplyTimelineFilters()
    {
        IEnumerable<TimelineEvent> events = CurrentCase.Events;

        if (!string.IsNullOrWhiteSpace(TimelineSearchText))
        {
            string query = TimelineSearchText.Trim();
            events = events.Where(e =>
                Contains(e.Process, query) ||
                Contains(e.Action, query) ||
                Contains(e.ObjectValue, query) ||
                Contains(e.Summary, query) ||
                Contains(e.TechniqueId, query) ||
                Contains(e.TechniqueName, query) ||
                Contains(e.Source, query) ||
                Contains(e.Category.ToString(), query) ||
                Contains(e.Severity.ToString(), query));
        }

        if (!string.Equals(SelectedProcessFilter, "All Processes", StringComparison.OrdinalIgnoreCase))
        {
            events = events.Where(e => string.Equals(e.Process, SelectedProcessFilter, StringComparison.OrdinalIgnoreCase));
        }

        if (SelectedProcessNode is not null)
        {
            var processKeys = GetProcessTreeKeys(SelectedProcessNode);
            events = events.Where(e => processKeys.Contains(ProcessKey(e.ProcessGuid, e.Process, e.Pid)));
        }

        TimeSpan? window = SelectedTimeRange switch
        {
            "Last 1 Minute" => TimeSpan.FromMinutes(1),
            "Last 5 Minutes" => TimeSpan.FromMinutes(5),
            "Last 15 Minutes" => TimeSpan.FromMinutes(15),
            _ => null
        };
        if (window is not null && CurrentCase.Events.Count > 0)
        {
            TimeSpan max = CurrentCase.Events.Max(e => e.Time);
            TimeSpan min = max - window.Value;
            events = events.Where(e => e.Time >= min);
        }

        events = events.Where(e => e.Category switch
        {
            EventCategory.Process => ShowProcessEvents,
            EventCategory.File => ShowFileEvents,
            EventCategory.Registry => ShowRegistryEvents,
            EventCategory.Network => ShowNetworkEvents,
            EventCategory.Dns => ShowDnsEvents,
            EventCategory.Api => ShowApiEvents,
            EventCategory.Behavior => ShowBehaviorEvents,
            _ => true
        });

        if (!ShowNoiseEvents)
        {
            events = events.Where(e => !IsNoisyEvent(e));
        }

        return events.OrderBy(e => e.Time).ToArray();
    }

    private static bool Contains(string value, string query) =>
        value.Contains(query, StringComparison.OrdinalIgnoreCase);

    private IReadOnlyList<TimelineEvent> GetRelatedEvidenceEvents()
    {
        if (SelectedEvent is null)
        {
            return Array.Empty<TimelineEvent>();
        }

        if (SelectedEvent.Category == EventCategory.Behavior)
        {
            var ids = ReadEvidenceIds(SelectedEvent.RawJson);
            return CurrentCase.Events
                .Where(e => ids.Contains(e.Id))
                .OrderBy(e => e.Time)
                .ToArray();
        }

        return CurrentCase.Events
            .Where(e => e.Id != SelectedEvent.Id &&
                        e.Pid == SelectedEvent.Pid &&
                        e.Category == SelectedEvent.Category &&
                        e.Action == SelectedEvent.Action)
            .OrderBy(e => e.Time)
            .Take(20)
            .ToArray();
    }

    private static HashSet<int> ReadEvidenceIds(string rawJson)
    {
        try
        {
            using var document = JsonDocument.Parse(rawJson);
            if (document.RootElement.TryGetProperty("evidence_event_ids", out var ids) && ids.ValueKind == JsonValueKind.Array)
            {
                return ids.EnumerateArray()
                    .Select(v => v.TryGetInt32(out int id) ? id : 0)
                    .Where(id => id > 0)
                    .ToHashSet();
            }
        }
        catch
        {
            // Malformed raw JSON should not break event navigation.
        }

        return [];
    }

    private HashSet<string> GetProcessTreeKeys(ProcessNode root)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ProcessKey(root.ProcessGuid, root.Name, root.Pid) };
        bool changed;
        do
        {
            changed = false;
            foreach (var process in CurrentCase.Processes)
            {
                if (process.ParentPid is int parentPid &&
                    keys.Any(k => k.EndsWith(":" + parentPid.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase)))
                {
                    changed |= keys.Add(ProcessKey(process.ProcessGuid, process.Name, process.Pid));
                }
            }
        }
        while (changed);

        return keys;
    }

    private static string ProcessKey(string processGuid, string name, int pid) =>
        string.IsNullOrWhiteSpace(processGuid)
            ? name + ":" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : processGuid + ":" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static bool IsNoisyEvent(TimelineEvent e)
    {
        if (e.Category == EventCategory.Behavior || e.Severity is EventSeverity.High or EventSeverity.Critical)
        {
            return false;
        }

        if (e.Source == "Hook" && e.Process == "hook")
        {
            return true;
        }

        if (e.Action.EndsWith("_hooks_installed", StringComparison.OrdinalIgnoreCase) ||
            e.Action.EndsWith("_hooks_failed", StringComparison.OrdinalIgnoreCase) ||
            e.Action is "initialized" or "shutdown")
        {
            return true;
        }

        if (e.Action is "GetTickCount" or "QueryPerformanceCounter" or "GetComputerNameW" or "GetUserNameW" or "ReleaseDC")
        {
            return true;
        }

        if (e.Category == EventCategory.Module &&
            e.Severity is EventSeverity.Low or EventSeverity.Informational &&
            (Contains(e.ObjectValue, "\\windows\\system32\\") || Contains(e.ObjectValue, "\\windows\\syswow64\\")))
        {
            return true;
        }

        return false;
    }

    private void LoadRecentCases()
    {
        RecentCases.Clear();
        var config = new MrtwConfigService().Load();
        foreach (var summary in new CaseService().List(config.Workspace).Take(20))
        {
            string type = Path.GetExtension(summary.SampleName).TrimStart('.').ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(type))
            {
                type = "CASE";
            }

            RecentCases.Add(new CaseListItem(summary.CaseName, type, summary.Sha256, summary.StartedAt.ToString("yyyy/MM/dd HH:mm:ss"), summary.Status));
        }
    }

    private static IReadOnlyList<ProcessNode> BuildLiveProcessNodes(IReadOnlyList<TimelineEvent> events)
    {
        var now = DateTimeOffset.Now;
        var started = events.Count == 0 ? now : now.Subtract(events.Max(e => e.Time));
        return events
            .Where(e => !string.IsNullOrWhiteSpace(e.Process))
            .GroupBy(e => new { e.ProcessGuid, e.Process, e.Pid })
            .Select(g => new ProcessNode(
                g.Key.Process,
                g.Key.Pid,
                null,
                string.IsNullOrWhiteSpace(g.Key.ProcessGuid) ? StableProcessGuid("case-live", g.Key.Pid, started.Add(g.Min(e => e.Time))) : g.Key.ProcessGuid,
                string.Empty,
                string.Empty,
                started.Add(g.Min(e => e.Time)),
                null,
                g.Count(),
                g.Count(e => e.Category == EventCategory.Network),
                g.Count(e => e.Category == EventCategory.File),
                g.Count(e => e.Category == EventCategory.Registry)))
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static TimelineEvent[] AttachLiveProcessGuids(IReadOnlyList<TimelineEvent> events, IReadOnlyList<ProcessNode> processes, string caseId, DateTimeOffset startedAt)
    {
        var byPidAndName = processes
            .GroupBy(p => ProcessLookupKey(p.Pid, p.Name))
            .ToDictionary(g => g.Key, g => g.OrderBy(p => p.StartTime).First().ProcessGuid, StringComparer.OrdinalIgnoreCase);
        var uniqueByPid = processes
            .Where(p => p.Pid > 0)
            .GroupBy(p => p.Pid)
            .Where(g => g.Count() == 1)
            .ToDictionary(g => g.Key, g => g.First().ProcessGuid);

        return events.Select(e =>
        {
            if (!string.IsNullOrWhiteSpace(e.ProcessGuid))
            {
                return e;
            }

            string processGuid = byPidAndName.TryGetValue(ProcessLookupKey(e.Pid, e.Process), out string? existing)
                ? existing
                : e.Pid > 0 && uniqueByPid.TryGetValue(e.Pid, out existing)
                    ? existing
                : StableProcessGuid(caseId, e.Pid, startedAt.Add(e.Time));
            return e with { ProcessGuid = processGuid };
        }).ToArray();
    }

    private IReadOnlyList<ArtifactItem> BuildArtifactItems(IEnumerable<TimelineEvent> events, string type)
    {
        var materialized = events.Where(e => !string.IsNullOrWhiteSpace(e.ObjectValue)).ToArray();
        if (materialized.Length == 0)
        {
            return Array.Empty<ArtifactItem>();
        }

        DateTimeOffset baseTime = CurrentCase.StartedAt == default ? DateTimeOffset.Now : CurrentCase.StartedAt;
        return materialized
            .GroupBy(e => e.ObjectValue, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ArtifactItem(
                type,
                g.Key,
                baseTime.Add(g.Min(e => e.Time)),
                baseTime.Add(g.Max(e => e.Time)),
                g.Count(),
                string.Join(", ", g.Select(e => e.Process).Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4)),
                g.Any(e => e.Severity is EventSeverity.Critical or EventSeverity.High) ? EventSeverity.High : g.Any(e => e.Severity == EventSeverity.Medium) ? EventSeverity.Medium : EventSeverity.Low))
            .OrderByDescending(a => a.EventCount)
            .ThenBy(a => a.Value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<ArtifactItem> BuildLiveArtifacts(IReadOnlyList<TimelineEvent> events, IReadOnlyList<ProcessNode> processes)
    {
        var now = DateTimeOffset.Now;
        var started = events.Count == 0 ? now : now.Subtract(events.Max(e => e.Time));
        return events
            .Where(e => e.Category is EventCategory.File or EventCategory.Registry or EventCategory.Network or EventCategory.Dns or EventCategory.Api)
            .GroupBy(e => e.Category)
            .Select(g => new ArtifactItem(
                g.Key.ToString(),
                string.Join(", ", g.Select(e => e.ObjectValue).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
                started.Add(g.Min(e => e.Time)),
                started.Add(g.Max(e => e.Time)),
                g.Count(),
                string.Join(", ", processes.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Take(4)),
                g.Any(e => e.Severity is EventSeverity.Critical or EventSeverity.High) ? EventSeverity.High : g.Any(e => e.Severity == EventSeverity.Medium) ? EventSeverity.Medium : EventSeverity.Low))
            .OrderByDescending(a => a.EventCount)
            .ToArray();
    }

    private static bool ContainsAny(string value, params string[] needles) =>
        needles.Any(n => value.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static string StableProcessGuid(string caseId, int pid, DateTimeOffset start) =>
        $"{caseId}:{pid}:{start.UtcTicks}";

    private static string ProcessLookupKey(int pid, string process) =>
        $"{pid}:{process}";

    private static CaseData EmptyCase() => new(
        "case-empty",
        "No case loaded",
        string.Empty,
        string.Empty,
        string.Empty,
        DateTimeOffset.Now,
        TimeSpan.Zero,
        null,
        Array.Empty<ProcessNode>(),
        Array.Empty<TimelineEvent>(),
        Array.Empty<ArtifactItem>(),
        Array.Empty<NetworkSession>(),
        string.Empty);

    private static StaticAnalysisResult EmptyStaticAnalysis() => new(
        string.Empty,
        string.Empty,
        0,
        string.Empty,
        string.Empty,
        string.Empty,
        string.Empty,
        string.Empty,
        null,
        string.Empty,
        Array.Empty<string>(),
        Array.Empty<string>(),
        Array.Empty<PeSectionInfo>(),
        Array.Empty<string>(),
        false,
        false,
        0);

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private static string ToDisplayName(string value) =>
        string.Join(' ', value.Split('-', StringSplitOptions.RemoveEmptyEntries).Select(part => char.ToUpperInvariant(part[0]) + part[1..]));
}

public sealed record CaseListItem(string Name, string Type, string Sha256, string Time, string Status);

public sealed class ExportSettings
{
    public bool HtmlReport { get; set; } = true;
    public bool CsvTimeline { get; set; } = true;
    public bool CsvArtifacts { get; set; } = true;
    public bool JsonCase { get; set; } = true;
    public bool JsonlRawEvents { get; set; } = true;
    public bool SqliteBundle { get; set; } = true;
    public bool IncludeSample { get; set; }
    public bool IncludeRaw { get; set; } = true;
    public bool CompressOutput { get; set; } = true;

    public ExportOptions ToExportOptions(bool privacyMode = false)
    {
        var formats = new List<string>();
        if (HtmlReport)
        {
            formats.Add("html");
        }

        if (CsvTimeline || CsvArtifacts)
        {
            formats.Add("csv");
        }

        if (JsonCase)
        {
            formats.Add("json");
        }

        if (JsonlRawEvents)
        {
            formats.Add("jsonl");
        }

        if (SqliteBundle)
        {
            formats.Add("sqlite");
        }

        return new ExportOptions(formats.Count == 0 ? "json" : string.Join(',', formats), privacyMode, IncludeSample, IncludeRaw, CompressOutput);
    }

    public ExportSettings Clone() => new()
    {
        HtmlReport = HtmlReport,
        CsvTimeline = CsvTimeline,
        CsvArtifacts = CsvArtifacts,
        JsonCase = JsonCase,
        JsonlRawEvents = JsonlRawEvents,
        SqliteBundle = SqliteBundle,
        IncludeSample = IncludeSample,
        IncludeRaw = IncludeRaw,
        CompressOutput = CompressOutput
    };
}

public sealed record ProfileOption(
    string Id,
    string DisplayName,
    int DurationSeconds,
    bool EnableEtw,
    bool EnableHook,
    bool SnapshotBefore,
    bool SnapshotAfter,
    string NetworkMode,
    string TimeoutAction,
    string Description)
{
    public string DurationText => $"{DurationSeconds}s";
}
