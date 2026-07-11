using MRTW.Collectors.Etw;
using MRTW.Core;

var tests = new List<(string Name, Action Body)>
{
    ("network modes normalize", TestNetworkModes),
    ("unsupported network mode fails", TestInvalidNetworkMode),
    ("shared orchestrator produces quality metadata", TestOrchestratorQuality),
    ("SQLite preserves UTC and quality", TestSqliteRoundTrip),
    ("behavior correlation remains deterministic", TestBehaviorCorrelation)
};

int failures = 0;
foreach (var test in tests)
{
    try
    {
        test.Body();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception ex)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {test.Name}: {ex}");
    }
}
Console.WriteLine($"{tests.Count - failures}/{tests.Count} regression tests passed.");
return failures == 0 ? 0 : 1;

static void TestNetworkModes()
{
    Equal("observe", NetworkContainmentService.NormalizeMode("on"));
    Equal("block", NetworkContainmentService.NormalizeMode("off"));
    Equal("isolated", NetworkContainmentService.NormalizeMode("isolate"));
}

static void TestInvalidNetworkMode()
{
    Throws<ArgumentException>(() => NetworkContainmentService.NormalizeMode("pretend"));
}

static void TestOrchestratorQuality()
{
    string sample = Environment.ProcessPath ?? typeof(AnalysisOrchestrator).Assembly.Location;
    var profile = new ExecutionProfile(sample, "exe", "none", null, $"\"{sample}\"",
        Path.GetDirectoryName(sample)!, 1, true, false, false, false, "observe", ExecuteTarget: false);
    CaseData data = new AnalysisOrchestrator().Collect(profile, null);
    True(data.Quality is not null, "quality missing");
    Equal("skipped", data.Quality!.Collectors.Single(c => c.Collector == "ETW").Status);
    True(data.Events.All(e => e.CapturedAtUtc.HasValue), "UTC capture time missing");
}

static void TestSqliteRoundTrip()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-regression-" + Guid.NewGuid().ToString("N"));
    try
    {
        Directory.CreateDirectory(root);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var quality = new CaseQuality("healthy",
            [new CollectorHealth("Runtime", "healthy", now, now, 1, 0)], "observe", true);
        var item = new TimelineEvent(1, TimeSpan.Zero, "test.exe", 42, EventCategory.Process,
            "Process Start", "test.exe", "test", EventSeverity.Low, "Regression", "{}", CapturedAtUtc: now);
        var data = new CaseData("case-test", "case-test", "test.exe", "test.exe", "hash", now,
            TimeSpan.Zero, null, [], [item], [], [], "notes", quality);
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("sqlite", Compress: false));
        CaseData loaded = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        Equal(now.ToString("O"), loaded.Events.Single().CapturedAtUtc!.Value.ToString("O"));
        Equal("healthy", loaded.Quality!.OverallStatus);
    }
    finally
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, true);
        }
    }
}

static void TestBehaviorCorrelation()
{
    var events = new[]
    {
        E(1, "VirtualAllocEx"), E(2, "WriteProcessMemory"), E(3, "CreateRemoteThread")
    };
    var correlated = BehaviorCorrelator.Correlate(events);
    Equal(1, correlated.Count(e => e.Action == "Process Injection Detected"));
    Equal(correlated.Count, correlated.Select(e => e.Id).Distinct().Count());
}

static TimelineEvent E(int id, string action) =>
    new(id, TimeSpan.FromMilliseconds(id), "sample.exe", 7, EventCategory.Api, action, "", "",
        EventSeverity.Medium, "Regression", "{}", CapturedAtUtc: DateTimeOffset.UtcNow);

static void True(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"expected={expected}, actual={actual}");
}

static void Throws<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}
