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

        var data = new SnapshotData(
            DateTimeOffset.UtcNow,
            files
                .GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(f => f.LastWriteUtc).First())
                .OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            CaptureRegistry(state),
            CaptureTcpConnections());
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

        return new SnapshotDiff(addedFiles, modifiedFiles, deletedFiles, addedReg, modifiedReg, deletedReg, newTcp);
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

            foreach (string name in key.GetValueNames())
            {
                if (state.ShouldStop) return;
                values.Add(new RegistrySnapshotEntry(displayKey, name, Convert.ToString(key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty));
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
                foreach (string name in key.GetValueNames().Take(256)) { if (state.ShouldStop) return; values.Add(new RegistrySnapshotEntry(display, name, Convert.ToString(key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames), System.Globalization.CultureInfo.InvariantCulture) ?? "")); }
                if (remaining > 0) foreach (string child in key.GetSubKeyNames().Take(2048)) Walk(path + "\\" + child, remaining - 1);
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

    private sealed class CaptureState(CancellationToken cancellationToken, int fileLimit, TimeSpan timeLimit, System.Diagnostics.Stopwatch stopwatch)
    {
        public int VisitedFiles { get; set; }
        public TimeSpan TimeLimit => timeLimit;
        public bool ItemLimitReached => VisitedFiles >= fileLimit;
        public bool ShouldStop => cancellationToken.IsCancellationRequested || ItemLimitReached || stopwatch.Elapsed >= timeLimit;
    }
}
