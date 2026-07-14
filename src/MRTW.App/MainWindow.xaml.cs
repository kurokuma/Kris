using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Threading;
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
    private LiveUpdateQueue? _liveQueue;
    private int _runGeneration;
    private bool _closePending;

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

    /// <summary>Opt-in UI-test helper. It is intentionally unavailable unless the test gate is set.</summary>
    public async Task LoadSmokeTargetAsync(string targetPath)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("MRTW_GUI_TESTS"), "1", StringComparison.Ordinal))
            throw new InvalidOperationException("GUI smoke support is disabled.");
        var analysis = await Task.Run(() => new StaticAnalysisService().Analyze(targetPath));
        if (!_viewModel.IsMonitoring) _viewModel.SelectTarget(targetPath, analysis);
    }

    public async Task LoadSmokeCaseAsync(string casePath)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("MRTW_GUI_TESTS"), "1", StringComparison.Ordinal))
            throw new InvalidOperationException("GUI smoke support is disabled.");
        var data = await Task.Run(() => new CaseService().Load(casePath));
        if (!_viewModel.IsMonitoring) _viewModel.LoadCaseData(data);
    }

    public async Task ExportSmokeCaseAsync(string outputRoot)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("MRTW_GUI_TESTS"), "1", StringComparison.Ordinal))
            throw new InvalidOperationException("GUI smoke support is disabled.");
        await Task.Run(() => _viewModel.ExportCase(_viewModel.CurrentCase, outputRoot, privacyMode: true));
        _viewModel.StatusText = "Case exported";
    }

    private async void OpenTarget_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open analysis target",
            Filter = "Analysis targets (*.exe;*.dll;*.lnk;*.ps1;*.js;*.vbs;*.msi;*.zip;*.doc;*.xls;*.ppt;*.docx;*.xlsx;*.pptx)|*.exe;*.dll;*.lnk;*.ps1;*.js;*.vbs;*.msi;*.zip;*.doc;*.xls;*.ppt;*.docx;*.xlsx;*.pptx|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == true)
        {
            string path = dialog.FileName;
            try
            {
                _viewModel.StatusText = "Analyzing target...";
                var analysis = await Task.Run(() => new StaticAnalysisService().Analyze(path));
                if (!_viewModel.IsMonitoring) _viewModel.SelectTarget(path, analysis);
            }
            catch (Exception ex)
            {
                _viewModel.StatusText = "Ready";
                MessageBox.Show(this, ex.Message, "MRTW Static Analysis Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private async void OpenCase_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open MRTW case",
            Filter = "MRTW case (case.json;case.sqlite)|case.json;case.sqlite|JSON files (*.json)|*.json|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == true)
        {
            try
            {
                string path = dialog.FileName;
                _viewModel.StatusText = "Opening case...";
                var data = await Task.Run(() => new CaseService().Load(path));
                if (!_viewModel.IsMonitoring)
                {
                    _viewModel.LoadCaseData(data);
                    ScrollTimelineToEnd();
                }
            }
            catch (Exception ex)
            {
                _viewModel.StatusText = "Ready";
                MessageBox.Show(this, ex.Message, "MRTW Open Case Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
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

        Task<CaseData>? task = null;
        CancellationTokenSource? cancellation = null;
        try
        {
            var profile = _viewModel.PrepareRun();
            _viewModel.BeginLiveRun(profile);
            cancellation = new CancellationTokenSource();
            _runCancellation = cancellation;
            int generation = Interlocked.Increment(ref _runGeneration);
            var liveQueue = new LiveUpdateQueue(generation);
            _liveQueue = liveQueue;
            _runTimer.Start();
            task = Task.Run(() => new AnalysisOrchestrator().Collect(
                profile,
                _viewModel.StaticAnalysis,
                cancellation.Token,
                timelineEvent => QueueLiveEvent(liveQueue, timelineEvent),
                session => QueueLiveNetworkSession(liveQueue, session)));
            _runTask = task;
            var data = await task;
            if (generation == Volatile.Read(ref _runGeneration))
            {
                _runTimer.Stop();
                _viewModel.CompleteRun(data, cancellation.IsCancellationRequested);
                ScrollTimelineToEnd();
            }
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
            if (task is not null && ReferenceEquals(_runTask, task))
            {
                _runTimer.Stop();
                _runCancellation?.Dispose();
                _runCancellation = null;
                _runTask = null;
            }
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

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string outputRoot = Path.Combine(AppContext.BaseDirectory, "out");
            var snapshot = _viewModel.CurrentCase;
            _viewModel.StatusText = "Exporting case...";
            string caseDir = await Task.Run(() => _viewModel.ExportCase(snapshot, outputRoot));
            _viewModel.StatusText = "Case exported";
            MessageBox.Show(this, $"Case exported:\n{caseDir}", "MRTW Export", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _viewModel.StatusText = "Export failed";
            MessageBox.Show(this, ex.Message, "MRTW Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
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

    private void QueueLiveEvent(LiveUpdateQueue queue, TimelineEvent timelineEvent)
    {
        if (!ReferenceEquals(queue, Volatile.Read(ref _liveQueue)) || queue.Generation != Volatile.Read(ref _runGeneration)) return;
        queue.Enqueue(timelineEvent);
        ScheduleLiveFlush(queue);
    }

    private void QueueLiveNetworkSession(LiveUpdateQueue queue, NetworkSession session)
    {
        if (!ReferenceEquals(queue, Volatile.Read(ref _liveQueue)) || queue.Generation != Volatile.Read(ref _runGeneration)) return;
        queue.Enqueue(session);
        ScheduleLiveFlush(queue);
    }

    private void ScheduleLiveFlush(LiveUpdateQueue queue)
    {
        if (!queue.TrySchedule()) return;
        Dispatcher.BeginInvoke(() => FlushLiveUpdates(queue), DispatcherPriority.Background);
    }

    private void FlushLiveUpdates(LiveUpdateQueue queue)
    {
        queue.MarkFlushed();
        if (!ReferenceEquals(queue, Volatile.Read(ref _liveQueue)) || queue.Generation != Volatile.Read(ref _runGeneration) || !_viewModel.IsMonitoring)
        {
            return;
        }
        var events = queue.DequeueEvents(256);
        _viewModel.AppendLiveEvents(events);
        _viewModel.AppendLiveNetworkSessions(queue.DequeueNetworkSessions(128));
        _viewModel.SetLiveQueueDropCount(queue.DroppedEvents + queue.DroppedNetworkSessions);
        if (!queue.IsEmpty) ScheduleLiveFlush(queue);
        if (events.Count > 0) ScrollTimelineToEnd();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_closePending && _runTask is { IsCompleted: false })
        {
            e.Cancel = true;
            _closePending = true;
            Interlocked.Increment(ref _runGeneration);
            _liveQueue = null;
            StopCurrentRun();
            _ = AwaitCloseAsync(_runTask);
            return;
        }
        base.OnClosing(e);
    }

    private async Task AwaitCloseAsync(Task task)
    {
        try { await task; } catch { }
        _ = Dispatcher.BeginInvoke(Close);
    }

    private sealed class LiveUpdateQueue(int generation)
    {
        private const int EventCapacity = 10_000;
        private const int NetworkCapacity = 2_000;
        private readonly ConcurrentQueue<TimelineEvent> _events = new();
        private readonly ConcurrentQueue<NetworkSession> _network = new();
        private int _eventCount, _networkCount, _scheduled;
        private long _droppedEvents, _droppedNetwork;
        public int Generation { get; } = generation;
        public long DroppedEvents => Interlocked.Read(ref _droppedEvents);
        public long DroppedNetworkSessions => Interlocked.Read(ref _droppedNetwork);
        public bool IsEmpty => Volatile.Read(ref _eventCount) == 0 && Volatile.Read(ref _networkCount) == 0;
        public void Enqueue(TimelineEvent value) { if (Interlocked.Increment(ref _eventCount) > EventCapacity) { Interlocked.Decrement(ref _eventCount); Interlocked.Increment(ref _droppedEvents); return; } _events.Enqueue(value); }
        public void Enqueue(NetworkSession value) { if (Interlocked.Increment(ref _networkCount) > NetworkCapacity) { Interlocked.Decrement(ref _networkCount); Interlocked.Increment(ref _droppedNetwork); return; } _network.Enqueue(value); }
        public List<TimelineEvent> DequeueEvents(int maximum) { var result = new List<TimelineEvent>(maximum); while (result.Count < maximum && _events.TryDequeue(out var value)) { Interlocked.Decrement(ref _eventCount); result.Add(value); } return result; }
        public List<NetworkSession> DequeueNetworkSessions(int maximum) { var result = new List<NetworkSession>(maximum); while (result.Count < maximum && _network.TryDequeue(out var value)) { Interlocked.Decrement(ref _networkCount); result.Add(value); } return result; }
        public bool TrySchedule() => Interlocked.Exchange(ref _scheduled, 1) == 0;
        public void MarkFlushed() => Interlocked.Exchange(ref _scheduled, 0);
    }

}
