using MRTW.Collectors.Etw;
using MRTW.Core;
using Microsoft.Data.Sqlite;
using System.IO.Compression;

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
    finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
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
