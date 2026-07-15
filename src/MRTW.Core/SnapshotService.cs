using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace MRTW.Core;

public sealed class SnapshotService
{
    private const int InteractiveFileLimit = 2_000;
    private static readonly TimeSpan InteractiveTimeLimit = TimeSpan.FromSeconds(8);
    private readonly IHostSecuritySnapshotProvider _hostSecurityProvider;

    public SnapshotService(IHostSecuritySnapshotProvider? hostSecurityProvider = null)
        => _hostSecurityProvider = hostSecurityProvider ?? new WindowsHostSecuritySnapshotProvider();

    public SnapshotData Capture(ExecutionProfile profile)
        => Capture(profile, CancellationToken.None).Data;

    public SnapshotCaptureResult Capture(ExecutionProfile profile, CancellationToken cancellationToken, int fileLimit = InteractiveFileLimit, TimeSpan? timeLimit = null)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var state = new CaptureState(cancellationToken, Math.Max(1, fileLimit), timeLimit ?? InteractiveTimeLimit, stopwatch);
        var roots = GetSnapshotRoots(profile).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var files = new List<FileSnapshotEntry>();
        foreach (string root in roots)
        {
            if (state.ShouldStop) break;
            files.AddRange(CaptureFiles(root, state));
        }

        var persistence = CapturePersistence(cancellationToken);
        var hostSecurity = CaptureHostSecurity(cancellationToken);
        var data = new SnapshotData(
            DateTimeOffset.UtcNow,
            files
                .GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(f => f.LastWriteUtc).First())
                .OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            CaptureRegistry(state),
            CaptureTcpConnections(),
            persistence.Entries,
            persistence.Quality,
            hostSecurity.Entries,
            hostSecurity.Quality);
        bool canceled = cancellationToken.IsCancellationRequested;
        bool bounded = !canceled && (state.ItemLimitReached || stopwatch.Elapsed >= state.TimeLimit);
        string note = canceled ? "Snapshot canceled by user." : bounded ? $"Snapshot bounded after {state.VisitedFiles} files or {state.TimeLimit.TotalSeconds:0}s." : "Snapshot completed.";
        return new SnapshotCaptureResult(data, !canceled && !bounded, canceled, bounded, note);
    }

    public SnapshotDiff Diff(SnapshotData before, SnapshotData after)
    {
        var beforeFiles = before.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
        var afterFiles = after.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
        var addedFiles = after.Files.Where(f => !beforeFiles.ContainsKey(f.Path)).ToArray();
        var modifiedFiles = after.Files
            .Where(f => beforeFiles.TryGetValue(f.Path, out var old) && (old.Size != f.Size || old.LastWriteUtc != f.LastWriteUtc || (!string.IsNullOrEmpty(old.Sha256) && old.Sha256 != f.Sha256)))
            .ToArray();
        var deletedFiles = before.Files.Where(f => !afterFiles.ContainsKey(f.Path)).Select(f => f.Path).ToArray();

        var beforeReg = before.RegistryValues.ToDictionary(RegistryKeyId, StringComparer.OrdinalIgnoreCase);
        var afterReg = after.RegistryValues.ToDictionary(RegistryKeyId, StringComparer.OrdinalIgnoreCase);
        var addedReg = after.RegistryValues.Where(v => !beforeReg.ContainsKey(RegistryKeyId(v))).ToArray();
        var modifiedReg = after.RegistryValues
            .Where(v => beforeReg.TryGetValue(RegistryKeyId(v), out var old) && old.Value != v.Value)
            .ToArray();
        var deletedReg = before.RegistryValues.Where(v => !afterReg.ContainsKey(RegistryKeyId(v))).Select(RegistryKeyId).ToArray();
        var beforeTcp = before.TcpConnections.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newTcp = after.TcpConnections.Where(c => !beforeTcp.Contains(c)).ToArray();

        var beforePersistence = PersistenceEntriesOrEmpty(before).ToDictionary(PersistenceId, StringComparer.OrdinalIgnoreCase);
        var afterPersistence = PersistenceEntriesOrEmpty(after).ToDictionary(PersistenceId, StringComparer.OrdinalIgnoreCase);
        var addedPersistence = PersistenceEntriesOrEmpty(after).Where(v => !beforePersistence.ContainsKey(PersistenceId(v))).ToArray();
        var modifiedPersistence = PersistenceEntriesOrEmpty(after).Where(v => beforePersistence.TryGetValue(PersistenceId(v), out var old) && !string.Equals(old.Fingerprint, v.Fingerprint, StringComparison.Ordinal)).ToArray();
        var deletedPersistence = PersistenceEntriesOrEmpty(before).Where(v => !afterPersistence.ContainsKey(PersistenceId(v))).ToArray();

        var beforeHost = HostSecurityEntriesOrEmpty(before).ToDictionary(HostSecurityId, StringComparer.OrdinalIgnoreCase);
        var afterHost = HostSecurityEntriesOrEmpty(after).ToDictionary(HostSecurityId, StringComparer.OrdinalIgnoreCase);
        var addedHost = HostSecurityEntriesOrEmpty(after).Where(v => !beforeHost.ContainsKey(HostSecurityId(v))).ToArray();
        var modifiedHost = HostSecurityEntriesOrEmpty(after).Where(v => beforeHost.TryGetValue(HostSecurityId(v), out var old) && !string.Equals(old.Fingerprint, v.Fingerprint, StringComparison.Ordinal)).ToArray();
        var hostChanges = modifiedHost.Select(v => new HostSecuritySnapshotChange(beforeHost[HostSecurityId(v)], v)).ToArray();
        var deletedHost = HostSecurityEntriesOrEmpty(before).Where(v => !afterHost.ContainsKey(HostSecurityId(v))).ToArray();
        return new SnapshotDiff(addedFiles, modifiedFiles, deletedFiles, addedReg, modifiedReg, deletedReg, newTcp,
            addedPersistence, modifiedPersistence, deletedPersistence, addedHost, modifiedHost, deletedHost, hostChanges);
    }

    public IReadOnlyList<PreservedFile> PreserveChangedFiles(SnapshotDiff diff, string caseId, string generation = "after", CancellationToken cancellationToken = default)
    {
        if (generation is not ("before" or "after")) throw new ArgumentException("Unsupported evidence generation.", nameof(generation));
        string root = Path.Combine(EvidencePathPolicy.Root(caseId), "evidence", "files", generation);
        Directory.CreateDirectory(root);
        var result = new List<PreservedFile>();
        long total = 0;
        const long perFileLimit = 32L * 1024 * 1024;
        const long totalLimit = 256L * 1024 * 1024;
        foreach (var entry in diff.AddedFiles.Concat(diff.ModifiedFiles).Where(f => f.Size <= 32 * 1024 * 1024).Take(128))
        {
            if (cancellationToken.IsCancellationRequested) break;
            try
            {
                var info = new FileInfo(entry.Path);
                if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                string pathId = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(entry.Path))).ToLowerInvariant()[..16];
                string safeName = $"{pathId}_{Path.GetFileName(entry.Path)}";
                string destination = Path.Combine(root, safeName);
                using var source = new FileStream(entry.Path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
                using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var hashState = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[64 * 1024];
                long copied = 0;
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (copied + read > perFileLimit || total + copied + read > totalLimit) throw new InvalidDataException("Evidence preservation limit exceeded.");
                    target.Write(buffer, 0, read); hashState.AppendData(buffer, 0, read); copied += read;
                }
                target.Flush(true);
                var after = new FileInfo(entry.Path);
                if (!after.Exists || (after.Attributes & FileAttributes.ReparsePoint) != 0 || after.Length != copied) { target.Dispose(); File.Delete(destination); continue; }
                string hash = Convert.ToHexString(hashState.GetHashAndReset()).ToLowerInvariant();
                total += copied;
                result.Add(new PreservedFile(entry.Path, destination, copied, hash, diff.AddedFiles.Contains(entry) ? "created" : "modified"));
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
        return result;
    }

    private static IEnumerable<string> GetSnapshotRoots(ExecutionProfile profile)
    {
        if (!string.IsNullOrWhiteSpace(profile.WorkingDirectory) && Directory.Exists(profile.WorkingDirectory))
        {
            yield return profile.WorkingDirectory;
        }

        string? temp = Path.GetTempPath();
        if (!string.IsNullOrWhiteSpace(temp) && Directory.Exists(temp))
        {
            yield return temp;
        }

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrWhiteSpace(appData) && Directory.Exists(appData))
        {
            yield return appData;
        }
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(localAppData) && Directory.Exists(localAppData)) yield return localAppData;
        string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrWhiteSpace(commonAppData) && Directory.Exists(commonAppData)) yield return commonAppData;
    }

    private static IEnumerable<FileSnapshotEntry> CaptureFiles(string root, CaptureState state)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        int visited = 0;
        while (stack.Count > 0 && visited < 5000 && !state.ShouldStop)
        {
            string current = stack.Pop();
            IEnumerable<string> directories = Array.Empty<string>();
            IEnumerable<string> files = Array.Empty<string>();
            try
            {
                directories = Directory.EnumerateDirectories(current);
                files = Directory.EnumerateFiles(current);
            }
            catch
            {
                continue;
            }

            foreach (string file in files)
            {
                if (state.ShouldStop) yield break;
                if (++visited > 5000)
                {
                    yield break;
                }

                FileInfo info;
                try
                {
                    info = new FileInfo(file);
                }
                catch
                {
                    continue;
                }

                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                string hash = "";
                try
                {
                    if (info.Length <= 32 * 1024 * 1024)
                    {
                        using var stream = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
                        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                        byte[] buffer = new byte[64 * 1024];
                        int read;
                        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            if (state.ShouldStop) break;
                            hasher.AppendData(buffer, 0, read);
                        }
                        if (!state.ShouldStop) hash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
                    }
                }
                catch { }
                if (state.ShouldStop) yield break;
                bool executable = new[] { ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ps1", ".js", ".vbs" }.Contains(info.Extension, StringComparer.OrdinalIgnoreCase);
                bool anomaly = info.LastWriteTimeUtc < info.CreationTimeUtc.AddDays(-1) || info.LastWriteTimeUtc > DateTime.UtcNow.AddMinutes(5);
                yield return new FileSnapshotEntry(info.FullName, info.Length, info.LastWriteTimeUtc, hash, info.Attributes.ToString(), info.CreationTimeUtc, executable, anomaly, CaptureAlternateStreams(info.FullName, state));
                state.VisitedFiles++;
            }

            foreach (string directory in directories.Take(250))
            {
                try { if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0) stack.Push(directory); } catch { }
            }
        }
    }

    private static IReadOnlyList<string> CaptureAlternateStreams(string path, CaptureState state)
    {
        if (!OperatingSystem.IsWindows()) return [];
        var streams = new List<string>(); IntPtr handle = FindFirstStreamW(path, 0, out var data, 0);
        if (handle == new IntPtr(-1)) return [];
        try { do { if (state.ShouldStop) break; if (!data.Name.Equals("::$DATA", StringComparison.OrdinalIgnoreCase)) streams.Add(data.Name); } while (streams.Count < 32 && FindNextStreamW(handle, out data)); }
        finally { FindClose(handle); }
        return streams;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StreamData { public long Size; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string Name; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr FindFirstStreamW(string fileName, int infoLevel, out StreamData data, int flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool FindNextStreamW(IntPtr handle, out StreamData data);
    [DllImport("kernel32.dll")] private static extern bool FindClose(IntPtr handle);

    private static IReadOnlyList<RegistrySnapshotEntry> CaptureRegistry(CaptureState state)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<RegistrySnapshotEntry>();
        }

        var values = new List<RegistrySnapshotEntry>();
        if (state.ShouldStop) return values;
        CaptureRegistryValues(values, Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", state);
        CaptureRegistryValues(values, Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", state);
        CaptureRegistryValues(values, Registry.CurrentUser, @"Software\Microsoft\Windows NT\CurrentVersion\Windows", @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows", state);
        CaptureRegistryValues(values, Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", state);
        CaptureRegistryValues(values, Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", state);
        CaptureRegistryValues(values, Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", state);
        CaptureRegistryTree(values, RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKLM64", 2, state);
        CaptureRegistryTree(values, RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKLM32", 2, state);
        CaptureRegistryTree(values, RegistryHive.LocalMachine, RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Services", "HKLM64", 2, state);
        CaptureRegistryTree(values, RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "HKLM64", 1, state);
        CaptureRegistryTree(values, RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Classes\CLSID", "HKLM64", 1, state);
        CaptureRegistryTree(values, RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Wbem\CIMOM", "HKCU", 1, state);
        return values.OrderBy(v => RegistryKeyId(v), StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureRegistryValues(List<RegistrySnapshotEntry> values, RegistryKey root, string subKey, string displayKey, CaptureState state)
    {
        try
        {
            using var key = root.OpenSubKey(subKey, false);
            if (key is null)
            {
                return;
            }

            foreach (string name in WindowsHostSecuritySnapshotProvider.EnumerateValueNames(key, 257))
            {
                if (state.ShouldStop) return;
                if (WindowsHostSecuritySnapshotProvider.TryReadBoundedValue(key, name, out string value)) values.Add(new RegistrySnapshotEntry(displayKey, name, value));
            }
        }
        catch
        {
            // Registry visibility depends on platform and privileges; missing data should not break a case.
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureRegistryTree(List<RegistrySnapshotEntry> values, RegistryHive hive, RegistryView view, string subKey, string displayRoot, int depth, CaptureState state)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            void Walk(string path, int remaining)
            {
                if (state.ShouldStop || values.Count >= 20_000) return;
                using var key = root.OpenSubKey(path, false); if (key is null) return;
                string display = $"{displayRoot}\\{path}";
                foreach (string name in WindowsHostSecuritySnapshotProvider.EnumerateValueNames(key, 257)) { if (state.ShouldStop) return; if (WindowsHostSecuritySnapshotProvider.TryReadBoundedValue(key, name, out string value)) values.Add(new RegistrySnapshotEntry(display, name, value)); }
                if (remaining > 0) foreach (string child in WindowsHostSecuritySnapshotProvider.EnumerateSubKeyNames(key, 2049)) Walk(path + "\\" + child, remaining - 1);
            }
            Walk(subKey, depth);
        }
        catch { }
    }

    public static IReadOnlyList<string> CaptureTcpConnections()
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections()
                .Select(c => $"{c.LocalEndPoint}->{c.RemoteEndPoint} {c.State}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string RegistryKeyId(RegistrySnapshotEntry value) => $"{value.KeyPath}\\{value.Name}";
    private static string PersistenceId(PersistenceSnapshotEntry value) => $"{value.Surface}|{value.Identity}";
    private static IReadOnlyList<PersistenceSnapshotEntry> PersistenceEntriesOrEmpty(SnapshotData data) => data.PersistenceEntries ?? [];
    private static string HostSecurityId(HostSecuritySnapshotEntry value) => $"{value.Surface}|{value.Identity}";
    private static IReadOnlyList<HostSecuritySnapshotEntry> HostSecurityEntriesOrEmpty(SnapshotData data) => data.HostSecurityEntries ?? [];

    private (IReadOnlyList<HostSecuritySnapshotEntry> Entries, IReadOnlyList<CollectorHealth> Quality) CaptureHostSecurity(CancellationToken cancellationToken)
    {
        string[] surfaces = ["Hosts", "WinINet", "WinHTTP", "Explorer", "Defender", "Firewall", "SecurityCenter"];
        var entries = new List<HostSecuritySnapshotEntry>(); var quality = new List<CollectorHealth>();
        foreach (string surface in surfaces) CaptureHostSecuritySurface(surface, entries, quality, cancellationToken);
        return (entries.OrderBy(HostSecurityId, StringComparer.OrdinalIgnoreCase).ToArray(), quality);
    }

    private void CaptureHostSecuritySurface(string surface, List<HostSecuritySnapshotEntry> entries, List<CollectorHealth> quality, CancellationToken cancellationToken)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); linked.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var capture = Task.Run(() => _hostSecurityProvider.Capture(surface, linked.Token), CancellationToken.None);
            int winner = Task.WaitAny([capture, Task.Delay(TimeSpan.FromSeconds(2))]);
            if (winner != 0 || cancellationToken.IsCancellationRequested) { linked.Cancel(); quality.Add(new(surface, cancellationToken.IsCancellationRequested ? "canceled" : "timeout", started, DateTimeOffset.UtcNow, 0, 0, "No partial host-security snapshot retained.")); return; }
            var result = capture.GetAwaiter().GetResult();
            if (linked.IsCancellationRequested) { quality.Add(new(surface, "timeout", started, DateTimeOffset.UtcNow, 0, 0, "No partial host-security snapshot retained.")); return; }
            int keep = Math.Min(512, result.Count); entries.AddRange(result.Take(keep));
            quality.Add(SummarizeHostSecuritySurface(surface, result, started, DateTimeOffset.UtcNow));
        }
        catch (PlatformNotSupportedException ex) { quality.Add(new(surface, "unavailable", started, DateTimeOffset.UtcNow, 0, 0, ex.Message)); }
        catch (UnauthorizedAccessException ex) { quality.Add(new(surface, "access-denied", started, DateTimeOffset.UtcNow, 0, 0, ex.Message)); }
        catch (OperationCanceledException) { quality.Add(new(surface, cancellationToken.IsCancellationRequested ? "canceled" : "timeout", started, DateTimeOffset.UtcNow, 0, 0, "No partial host-security snapshot retained.")); }
        catch (Exception ex) { quality.Add(new(surface, "unavailable", started, DateTimeOffset.UtcNow, 0, 0, ex.GetType().Name)); }
    }

    internal static CollectorHealth SummarizeHostSecuritySurfaceForTest(string surface, IReadOnlyList<HostSecuritySnapshotEntry> result)
        => SummarizeHostSecuritySurface(surface, result, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

    private static CollectorHealth SummarizeHostSecuritySurface(string surface, IReadOnlyList<HostSecuritySnapshotEntry> result, DateTimeOffset started, DateTimeOffset completed)
    {
        const int limit = 512;
        int kept = Math.Min(limit, result.Count);
        int valueLimited = result.Count(e => e.Value.StartsWith("value-limit:", StringComparison.Ordinal));
        int sizeUnavailable = result.Count(e => e.Value.StartsWith("value-size-unavailable", StringComparison.Ordinal));
        int valueNameLimited = result.Count(e => e.Value.StartsWith("value-name-limit", StringComparison.Ordinal));
        int subkeyNameLimited = result.Count(e => e.Value.StartsWith("subkey-name-limit", StringComparison.Ordinal));
        bool degraded = result.Count > limit || valueLimited > 0 || sizeUnavailable > 0 || valueNameLimited > 0 || subkeyNameLimited > 0;
        string message = string.Join(";", new[]
        {
            result.Count > limit ? "entry-limit" : "",
            valueLimited > 0 ? $"value-limit;values={valueLimited};bytes=bounded" : "",
            sizeUnavailable > 0 ? $"value-size-unavailable;values={sizeUnavailable}" : "",
            valueNameLimited > 0 ? $"value-name-limit;values={valueNameLimited}" : "",
            subkeyNameLimited > 0 ? $"subkey-name-limit;values={subkeyNameLimited}" : ""
        }.Where(x => x.Length > 0));
        long dropped = Math.Max(0, result.Count - kept) + valueLimited + sizeUnavailable + valueNameLimited + subkeyNameLimited;
        return new CollectorHealth(surface, degraded ? "degraded" : "healthy", started, completed, result.Count, dropped, message);
    }

    private static (IReadOnlyList<PersistenceSnapshotEntry> Entries, IReadOnlyList<CollectorHealth> Quality) CapturePersistence(CancellationToken cancellationToken)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        if (!OperatingSystem.IsWindows())
        {
            return ([], [new CollectorHealth("Persistence", "unavailable", started, DateTimeOffset.UtcNow, 0, 0, "Windows-only read-only persistence capture is unavailable on this OS.")]);
        }

        return CaptureWindowsPersistence(cancellationToken, started);
    }

    [SupportedOSPlatform("windows")]
    private static (IReadOnlyList<PersistenceSnapshotEntry> Entries, IReadOnlyList<CollectorHealth> Quality) CaptureWindowsPersistence(CancellationToken cancellationToken, DateTimeOffset started)
    {
        const int surfaceLimit = 512;
        var entries = new List<PersistenceSnapshotEntry>();
        var health = new List<CollectorHealth>();
        CapturePersistenceSurface("StartupFolder", token => CaptureStartupFolders(surfaceLimit, token), entries, health, cancellationToken, surfaceLimit, TimeSpan.FromSeconds(2));
        CapturePersistenceSurface("ScheduledTask", token => CaptureScheduledTasks(surfaceLimit, token), entries, health, cancellationToken, surfaceLimit, TimeSpan.FromSeconds(2));
        CapturePersistenceSurface("WindowsService", token => CaptureServices(surfaceLimit, token), entries, health, cancellationToken, surfaceLimit, TimeSpan.FromSeconds(2));
        CapturePersistenceSurface("WmiSubscription", token => CaptureWmiSubscriptions(surfaceLimit, token), entries, health, cancellationToken, surfaceLimit, TimeSpan.FromSeconds(2));
        return (entries.OrderBy(PersistenceId, StringComparer.OrdinalIgnoreCase).ToArray(), health);
    }

    private static void CapturePersistenceSurface(string name, Func<CancellationToken, IReadOnlyList<PersistenceSnapshotEntry>> capture, List<PersistenceSnapshotEntry> entries, List<CollectorHealth> health, CancellationToken cancellationToken, int limit, TimeSpan timeout)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        if (cancellationToken.IsCancellationRequested) { health.Add(new CollectorHealth(name, "canceled", started, DateTimeOffset.UtcNow, 0, 0, "Snapshot canceled.")); return; }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            // Capture implementations only query Windows APIs; no process, shell, or command interpreter is invoked.
            var task = Task.Run(() => capture(linked.Token), CancellationToken.None);
            if (!task.Wait(timeout))
            {
                linked.Cancel();
                try { task.Wait(TimeSpan.FromMilliseconds(250)); } catch (AggregateException) { /* Cancellation is expected; discard all results. */ }
                health.Add(new CollectorHealth(name, "timeout", started, DateTimeOffset.UtcNow, 0, 0, $"Read-only surface query exceeded {timeout.TotalSeconds:0.#} seconds; no partial result was retained."));
                return;
            }
            if (cancellationToken.IsCancellationRequested) { linked.Cancel(); health.Add(new CollectorHealth(name, "canceled", started, DateTimeOffset.UtcNow, 0, 0, "Snapshot canceled; no partial result was retained.")); return; }
            var allCaptured = task.GetAwaiter().GetResult();
            var captured = allCaptured.Take(limit).ToArray();
            long dropped = Math.Max(0, allCaptured.Count - captured.Length);
            entries.AddRange(captured);
            string status = dropped > 0 ? "degraded" : "available";
            string message = dropped > 0 ? $"read-only; limit={limit}; reason=entry-limit; retained={captured.Length}; dropped={dropped}" : $"read-only; limit={limit}";
            health.Add(new CollectorHealth(name, status, started, DateTimeOffset.UtcNow, captured.Length + dropped, dropped, message));
        }
        catch (UnauthorizedAccessException ex) { health.Add(new CollectorHealth(name, "access-denied", started, DateTimeOffset.UtcNow, 0, 0, ex.GetType().Name)); }
        catch (System.Security.SecurityException ex) { health.Add(new CollectorHealth(name, "access-denied", started, DateTimeOffset.UtcNow, 0, 0, ex.GetType().Name)); }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { health.Add(new CollectorHealth(name, "canceled", started, DateTimeOffset.UtcNow, 0, 0, "Snapshot canceled; no partial result was retained.")); }
        catch (Exception ex) { health.Add(new CollectorHealth(name, "unavailable", started, DateTimeOffset.UtcNow, 0, 0, ex.GetType().Name)); }
    }

    internal static (IReadOnlyList<PersistenceSnapshotEntry> Entries, CollectorHealth Health) CapturePersistenceSurfaceForTest(string name, Func<CancellationToken, IReadOnlyList<PersistenceSnapshotEntry>> capture, TimeSpan timeout)
    {
        var entries = new List<PersistenceSnapshotEntry>(); var quality = new List<CollectorHealth>();
        CapturePersistenceSurface(name, capture, entries, quality, CancellationToken.None, 512, timeout);
        return (entries, quality.Single());
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<PersistenceSnapshotEntry> CaptureStartupFolders(int limit, CancellationToken cancellationToken)
    {
        var output = new List<PersistenceSnapshotEntry>();
        string[] roots = [Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)];
        foreach (string root in roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
            foreach (string path in Directory.EnumerateFiles(root).Take(limit + 1 - output.Count))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var info = new FileInfo(path);
                output.Add(Persistence("StartupFolder", path, info.Name, path, $"{info.Length}|{info.LastWriteTimeUtc.Ticks}"));
                if (output.Count >= limit + 1) return output;
            }
        return output;
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<PersistenceSnapshotEntry> CaptureServices(int limit, CancellationToken cancellationToken)
    {
        var output = new List<PersistenceSnapshotEntry>();
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
        if (root is null) return output;
        foreach (string name in WindowsHostSecuritySnapshotProvider.EnumerateSubKeyNames(root, limit + 1))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var key = root.OpenSubKey(name, false); if (key is null) continue;
            string image = WindowsHostSecuritySnapshotProvider.TryReadBoundedValue(key, "ImagePath", out string imageValue) ? imageValue : "value-size-unavailable";
            string start = WindowsHostSecuritySnapshotProvider.TryReadBoundedValue(key, "Start", out string startValue) ? startValue : "value-size-unavailable";
            output.Add(Persistence("WindowsService", name, name, image, $"{image}|start={start}"));
        }
        return output;
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<PersistenceSnapshotEntry> CaptureScheduledTasks(int limit, CancellationToken cancellationToken)
    {
        Type? type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) throw new PlatformNotSupportedException("Task Scheduler COM is unavailable.");
        dynamic service = Activator.CreateInstance(type) ?? throw new InvalidOperationException("Task Scheduler COM activation failed.");
        try
        {
            service.Connect(); dynamic folder = service.GetFolder("\\");
            var output = new List<PersistenceSnapshotEntry>();
            var folders = new Stack<dynamic>(); folders.Push(folder);
            while (folders.Count > 0 && output.Count < limit + 1)
            {
                cancellationToken.ThrowIfCancellationRequested();
                dynamic current = folders.Pop();
                var children = new List<dynamic>();
                try { foreach (dynamic task in current.GetTasks(1))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string path = Convert.ToString(task.Path) ?? ""; string name = Convert.ToString(task.Name) ?? path;
                    // Do not request task XML. Action metadata is a read-only summary only.
                    string target = ""; dynamic? actions = null; dynamic? action = null;
                    try { actions = task.Definition.Actions; if (actions.Count > 0) { action = actions.Item(1); target = Convert.ToString(action.Path) ?? ""; } } catch { }
                    finally { ReleaseComObject(action); ReleaseComObject(actions); }
                    output.Add(Persistence("ScheduledTask", path, name, target, $"{target}|enabled={task.Enabled}"));
                    ReleaseComObject(task);
                    if (output.Count >= limit + 1) break;
                }
                if (output.Count < limit + 1) foreach (dynamic child in current.GetFolders(0)) children.Add(child);
                } finally { ReleaseComObject(current); }
                if (output.Count >= limit + 1) break;
                foreach (dynamic child in children) folders.Push(child);
            }
            return output;
        }
        finally { try { Marshal.FinalReleaseComObject(service); } catch { } }
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<PersistenceSnapshotEntry> CaptureWmiSubscriptions(int limit, CancellationToken cancellationToken)
    {
        Type? type = Type.GetTypeFromProgID("WbemScripting.SWbemLocator");
        if (type is null) throw new PlatformNotSupportedException("WMI COM is unavailable.");
        dynamic locator = Activator.CreateInstance(type) ?? throw new InvalidOperationException("WMI COM activation failed.");
        try
        {
            dynamic service = locator.ConnectServer(".", "root\\subscription");
            try
            {
                var filters = new Dictionary<string, (string Name, string Fingerprint)>(StringComparer.OrdinalIgnoreCase);
                foreach (dynamic filter in service.ExecQuery("SELECT __RELPATH, Name, Query, EventNamespace FROM __EventFilter"))
                {
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string reference = NormalizeWmiReference(Convert.ToString(filter.__RELPATH) ?? "");
                        string name = Convert.ToString(filter.Name) ?? ""; string query = Convert.ToString(filter.Query) ?? "";
                        filters[reference] = (name, Hash($"{Hash(query)}|namespace={filter.EventNamespace}"));
                    }
                    finally { ReleaseComObject(filter); }
                }
                var consumers = new Dictionary<string, (string Name, string Target, string Fingerprint)>(StringComparer.OrdinalIgnoreCase);
                foreach (dynamic consumer in service.ExecQuery("SELECT __RELPATH, Name FROM __EventConsumer"))
                {
                    try { cancellationToken.ThrowIfCancellationRequested(); consumers[NormalizeWmiReference(Convert.ToString(consumer.__RELPATH) ?? "")] = (Convert.ToString(consumer.Name) ?? "", "WMI event consumer", ""); }
                    finally { ReleaseComObject(consumer); }
                }
                foreach (dynamic consumer in service.ExecQuery("SELECT __RELPATH, Name, CommandLineTemplate FROM CommandLineEventConsumer"))
                {
                    try { cancellationToken.ThrowIfCancellationRequested(); string command = Convert.ToString(consumer.CommandLineTemplate) ?? ""; consumers[NormalizeWmiReference(Convert.ToString(consumer.__RELPATH) ?? "")] = (Convert.ToString(consumer.Name) ?? "", command, Hash(command)); }
                    finally { ReleaseComObject(consumer); }
                }
                foreach (dynamic consumer in service.ExecQuery("SELECT __RELPATH, Name, ScriptingEngine, ScriptText FROM ActiveScriptEventConsumer"))
                {
                    try { cancellationToken.ThrowIfCancellationRequested(); string engine = Convert.ToString(consumer.ScriptingEngine) ?? ""; string script = Convert.ToString(consumer.ScriptText) ?? ""; consumers[NormalizeWmiReference(Convert.ToString(consumer.__RELPATH) ?? "")] = (Convert.ToString(consumer.Name) ?? "", $"ActiveScriptEventConsumer ({engine}); script_sha256={Hash(script)}", Hash(script)); }
                    finally { ReleaseComObject(consumer); }
                }

                var output = new List<PersistenceSnapshotEntry>();
                foreach (dynamic binding in service.ExecQuery("SELECT Filter, Consumer FROM __FilterToConsumerBinding"))
                {
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string filterRef = NormalizeWmiReference(Convert.ToString(binding.Filter) ?? "");
                        string consumerRef = NormalizeWmiReference(Convert.ToString(binding.Consumer) ?? "");
                        if (!filters.TryGetValue(filterRef, out var filter) || !consumers.TryGetValue(consumerRef, out var consumer)) continue;
                        string identity = $"binding:{filterRef}|{consumerRef}";
                        string display = $"{filter.Name} -> {consumer.Name}";
                        output.Add(Persistence("WmiSubscription", identity, display, consumer.Target, $"filter={filter.Fingerprint}|consumer={consumer.Fingerprint}|{identity}"));
                        if (output.Count >= limit + 1) break;
                    }
                    finally { ReleaseComObject(binding); }
                }
                return output;
            }
            finally { ReleaseComObject(service); }
        }
        finally { ReleaseComObject(locator); }
    }

    internal static string NormalizeWmiReference(string value)
    {
        string normalized = value.Trim().Replace('/', '\\');
        int colon = normalized.IndexOf(':'); if (colon >= 0) normalized = normalized[(colon + 1)..];
        return normalized.Trim().ToLowerInvariant();
    }
    private static void ReleaseComObject(object? value)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (value is not null && Marshal.IsComObject(value)) try { Marshal.FinalReleaseComObject(value); } catch { }
    }

    private static PersistenceSnapshotEntry Persistence(string surface, string identity, string display, string target, string fingerprint) =>
        new(surface, identity, display, target, Hash(fingerprint));
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value ?? ""))).ToLowerInvariant();

    private sealed class CaptureState(CancellationToken cancellationToken, int fileLimit, TimeSpan timeLimit, System.Diagnostics.Stopwatch stopwatch)
    {
        public int VisitedFiles { get; set; }
        public TimeSpan TimeLimit => timeLimit;
        public bool ItemLimitReached => VisitedFiles >= fileLimit;
        public bool ShouldStop => cancellationToken.IsCancellationRequested || ItemLimitReached || stopwatch.Elapsed >= timeLimit;
    }
}
