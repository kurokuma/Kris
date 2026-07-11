using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace MRTW.Core;

public sealed class SnapshotService
{
    public SnapshotData Capture(ExecutionProfile profile)
    {
        var roots = GetSnapshotRoots(profile).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var files = new List<FileSnapshotEntry>();
        foreach (string root in roots)
        {
            files.AddRange(CaptureFiles(root));
        }

        return new SnapshotData(
            DateTimeOffset.UtcNow,
            files
                .GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(f => f.LastWriteUtc).First())
                .OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            CaptureRegistry(),
            CaptureTcpConnections());
    }

    public SnapshotDiff Diff(SnapshotData before, SnapshotData after)
    {
        var beforeFiles = before.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
        var afterFiles = after.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
        var addedFiles = after.Files.Where(f => !beforeFiles.ContainsKey(f.Path)).ToArray();
        var modifiedFiles = after.Files
            .Where(f => beforeFiles.TryGetValue(f.Path, out var old) && (old.Size != f.Size || old.LastWriteUtc != f.LastWriteUtc))
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
    }

    private static IEnumerable<FileSnapshotEntry> CaptureFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        int visited = 0;
        while (stack.Count > 0 && visited < 5000)
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

                yield return new FileSnapshotEntry(info.FullName, info.Length, info.LastWriteTimeUtc);
            }

            foreach (string directory in directories.Take(250))
            {
                stack.Push(directory);
            }
        }
    }

    private static IReadOnlyList<RegistrySnapshotEntry> CaptureRegistry()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<RegistrySnapshotEntry>();
        }

        var values = new List<RegistrySnapshotEntry>();
        CaptureRegistryValues(values, Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run");
        CaptureRegistryValues(values, Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce");
        return values.OrderBy(v => RegistryKeyId(v), StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureRegistryValues(List<RegistrySnapshotEntry> values, RegistryKey root, string subKey, string displayKey)
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
                values.Add(new RegistrySnapshotEntry(displayKey, name, Convert.ToString(key.GetValue(name), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty));
            }
        }
        catch
        {
            // Registry visibility depends on platform and privileges; missing data should not break a case.
        }
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
}
