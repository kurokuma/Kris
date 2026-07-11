using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using MRTW.Collectors.Etw;
using MRTW.Core;

namespace MRTW.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly DispatcherTimer _runTimer;
    private CancellationTokenSource? _runCancellation;
    private Task? _runTask;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel();
        DataContext = _viewModel;
        _viewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.FilteredEvents))
            {
                ScrollTimelineToEnd();
            }
        };
        _runTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _runTimer.Tick += (_, _) => _viewModel.UpdateRunDuration();
    }

    private void OpenTarget_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open analysis target",
            Filter = "Executable files (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == true)
        {
            _viewModel.SelectTarget(dialog.FileName);
        }
    }

    private void OpenCase_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open MRTW case",
            Filter = "MRTW case (case.json;case.sqlite)|case.json;case.sqlite|JSON files (*.json)|*.json|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == true)
        {
            _viewModel.LoadCase(dialog.FileName);
            ScrollTimelineToEnd();
        }
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        await StartAnalysisAsync(restart: false);
    }

    private async void Restart_Click(object sender, RoutedEventArgs e)
    {
        await StartAnalysisAsync(restart: true);
    }

    private async Task StartAnalysisAsync(bool restart)
    {
        if (_runTask is { IsCompleted: false })
        {
            if (!restart)
            {
                MessageBox.Show(this, "Analysis is already running.", "MRTW", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            StopCurrentRun();
            await _runTask;
        }

        try
        {
            var profile = _viewModel.PrepareRun();
            _viewModel.BeginLiveRun(profile);
            _runCancellation = new CancellationTokenSource();
            Task<EtwCollectionResult>? etwTask = null;
            bool etwStarted = false;
            _runTimer.Start();
            _runTask = Task.Run(() => new RuntimeCaseCollector().Collect(
                profile,
                _viewModel.StaticAnalysis,
                _runCancellation.Token,
                timelineEvent => Dispatcher.Invoke(() =>
                {
                    _viewModel.AppendLiveEvent(timelineEvent);
                    if (profile.EnableEtw && !etwStarted && timelineEvent.Pid > 0)
                    {
                        etwStarted = true;
                        int targetPid = timelineEvent.Pid;
                        TimeSpan? etwDuration = profile.DurationSeconds is int seconds ? TimeSpan.FromSeconds(Math.Max(1, seconds)) : null;
                        etwTask = Task.Run(() => new TraceEventEtwCollector().Collect(
                            new EtwCollectorOptions(targetPid, etwDuration),
                            _runCancellation.Token,
                            etwEvent => Dispatcher.BeginInvoke(() =>
                            {
                                _viewModel.AppendLiveEvent(etwEvent);
                                ScrollTimelineToEnd();
                            }),
                            session => Dispatcher.BeginInvoke(() => _viewModel.AppendLiveNetworkSession(session))));
                    }
                    ScrollTimelineToEnd();
                })));
            var data = await (Task<CaseData>)_runTask;
            if (etwTask is not null)
            {
                var etw = await etwTask;
                if (etw.Events.Count > 0 || etw.NetworkSessions.Count > 0)
                {
                    data = MergeEtw(data, etw);
                }
            }
            _runTimer.Stop();
            _viewModel.CompleteRun(data, _runCancellation.IsCancellationRequested);
            ScrollTimelineToEnd();
        }
        catch (InvalidOperationException ex)
        {
            _runTimer.Stop();
            _viewModel.FailRun("Ready");
            MessageBox.Show(this, ex.Message + "\n\nUse File > Open Target before Start.", "MRTW", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            _runTimer.Stop();
            _viewModel.FailRun("Analysis failed");
            MessageBox.Show(this, ex.Message, "MRTW Analysis Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _runCancellation?.Dispose();
            _runCancellation = null;
            _runTask = null;
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        StopCurrentRun();
    }

    private void StopCurrentRun()
    {
        if (_runTask is not { IsCompleted: false })
        {
            _viewModel.FailRun("Stopped");
            return;
        }

        _viewModel.MarkStopping();
        _runCancellation?.Cancel();
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ExportSettingsWindow(_viewModel.ExportSettings.Clone())
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true)
        {
            _viewModel.ExportSettings = dialog.Settings;
        }
    }

    private void ProfileSettings_Click(object sender, RoutedEventArgs e)
    {
        var config = new MrtwConfigService().Load();
        var hook = new NativeHookLauncher();
        string message =
            "Profile meaning:\n\n" +
            "Default: uses the configured default profile. In the built-in config this resolves to Full Capture.\n\n" +
            "Quick: fast first-pass analysis. Static metadata, snapshots, ETW, and standard runtime events are collected; native hook capture is off.\n\n" +
            "Full Capture: deeper runtime analysis. Native hook capture is enabled when the hook DLL and injector are available, with the same snapshot/runtime collection.\n\n" +
            "GUI runtime limit: none. Analysis continues until the target exits or Stop is pressed. CLI/config durations still apply to command-line runs.\n\n" +
            $"Configured default profile: {config.DefaultProfile}\n\n" +
            $"Native hook: {(hook.IsAvailable ? "Available" : "Not found")}\n{hook.HookDllPath}\n\n" +
            $"Injector:\n{hook.InjectorPath}";

        MessageBox.Show(this, message, "MRTW Profile Settings", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void RecentCases_Click(object sender, RoutedEventArgs e)
    {
        var builder = new StringBuilder();
        foreach (var item in _viewModel.RecentCases.Take(20))
        {
            builder.AppendLine($"{item.Time}  {item.Status}  {item.Name}");
        }

        MessageBox.Show(this, builder.Length == 0 ? "No recent cases were found." : builder.ToString(), "Recent Cases", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        string outputRoot = Path.Combine(AppContext.BaseDirectory, "out");
        string caseDir = _viewModel.ExportCurrentCase(outputRoot);
        MessageBox.Show(this, $"Case exported:\n{caseDir}", "MRTW Export", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void ResetFilters_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.ResetTimelineFilters();
        ScrollTimelineToEnd();
    }

    private void Filter_Click(object sender, RoutedEventArgs e)
    {
        ScrollTimelineToEnd();
    }

    private void ScrollTimelineToEnd()
    {
        Dispatcher.BeginInvoke(() =>
        {
            var last = _viewModel.FilteredEvents.LastOrDefault();
            if (last is not null)
            {
                TimelineGrid.ScrollIntoView(last);
            }
        }, DispatcherPriority.Background);
    }

    private static CaseData MergeEtw(CaseData data, EtwCollectionResult etw)
    {
        var processGuids = data.Processes
            .GroupBy(p => ProcessLookupKey(p.Pid, p.Name))
            .ToDictionary(g => g.Key, g => g.First().ProcessGuid, StringComparer.OrdinalIgnoreCase);
        var uniqueProcessGuids = data.Processes
            .Where(p => p.Pid > 0)
            .GroupBy(p => p.Pid)
            .Where(g => g.Count() == 1)
            .ToDictionary(g => g.Key, g => g.First().ProcessGuid);
        var events = data.Events
            .Concat(etw.Events)
            .OrderBy(e => e.Time)
            .Select((e, index) => e with
            {
                Id = index + 1,
                ProcessGuid = string.IsNullOrWhiteSpace(e.ProcessGuid) && processGuids.TryGetValue(ProcessLookupKey(e.Pid, e.Process), out string? processGuid)
                    ? processGuid
                    : string.IsNullOrWhiteSpace(e.ProcessGuid)
                        ? e.Pid > 0 && uniqueProcessGuids.TryGetValue(e.Pid, out processGuid)
                            ? processGuid
                            : StableProcessGuid(data.CaseId, e.Pid, data.StartedAt.Add(e.Time))
                        : e.ProcessGuid
            })
            .ToArray();

        var network = data.NetworkSessions.Concat(etw.NetworkSessions).ToArray();
        return data with
        {
            Events = events,
            NetworkSessions = network,
            AnalystNotes = data.AnalystNotes + (etw.Started ? " ETW process, image-load, TCP, and DNS telemetry was merged into the timeline." : $" ETW collection was unavailable: {etw.ErrorMessage}")
        };
    }

    private static string StableProcessGuid(string caseId, int pid, DateTimeOffset start) =>
        $"{caseId}:{pid}:{start.UtcTicks}";

    private static string ProcessLookupKey(int pid, string process) =>
        $"{pid}:{process}";
}
