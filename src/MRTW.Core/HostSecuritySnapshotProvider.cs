using Microsoft.Win32;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace MRTW.Core;

/// <summary>Injectable read-only source for host security configuration snapshots.</summary>
public interface IHostSecuritySnapshotProvider
{
    IReadOnlyList<HostSecuritySnapshotEntry> Capture(string surface, CancellationToken cancellationToken);
}

/// <summary>Windows registry/file reads only; this type intentionally contains no setters, process launchers, or firewall APIs.</summary>
public sealed class WindowsHostSecuritySnapshotProvider : IHostSecuritySnapshotProvider
{
    private static readonly byte[] NulSeparator = [0];
    public IReadOnlyList<HostSecuritySnapshotEntry> Capture(string surface, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows-only read-only host security capture is unavailable on this OS.");
        cancellationToken.ThrowIfCancellationRequested();
        return surface switch
        {
            "Hosts" => Hosts(cancellationToken),
            "WinINet" => Registry("WinINet", RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", cancellationToken),
            "WinHTTP" => Registry("WinHTTP", RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections", cancellationToken),
            "Explorer" => Registry("Explorer", RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", cancellationToken),
            "Defender" => RegistryMany("Defender", RegistryHive.LocalMachine, [
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes"], cancellationToken),
            "Firewall" => RegistryMany("Firewall", RegistryHive.LocalMachine, [
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"], cancellationToken),
            "SecurityCenter" => Registry("SecurityCenter", RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Security Center", cancellationToken),
            _ => []
        };
    }

    private static IReadOnlyList<HostSecuritySnapshotEntry> Hosts(CancellationToken token)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        if (!File.Exists(path)) return [];
        var info = new FileInfo(path); const long maxBytes = 1024 * 1024;
        if (info.Length > maxBytes) throw new InvalidDataException("hosts file exceeds the 1 MiB read-only snapshot limit.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[64 * 1024]; long total = 0; int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            token.ThrowIfCancellationRequested(); total += read;
            if (total > maxBytes) throw new InvalidDataException("hosts file exceeds the 1 MiB read-only snapshot limit.");
            hash.AppendData(buffer, 0, read);
        }
        string fingerprint = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        return [new("Hosts", path, $"sha256={fingerprint};bytes={total}", fingerprint)];
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<HostSecuritySnapshotEntry> RegistryMany(string surface, RegistryHive hive, IReadOnlyList<string> paths, CancellationToken token)
    {
        var entries = new List<HostSecuritySnapshotEntry>();
        foreach (string path in paths)
        {
            token.ThrowIfCancellationRequested();
            // Each reader is read-only; retain one extra total item for the shared 512-entry quality check.
            entries.AddRange(Registry(surface, hive, path, token));
            if (entries.Count >= 513) break;
        }
        return entries.OrderBy(e => e.Identity, StringComparer.OrdinalIgnoreCase).Take(513).ToArray();
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<HostSecuritySnapshotEntry> Registry(string surface, RegistryHive hive, string path, CancellationToken token)
    {
        var entries = new List<HostSecuritySnapshotEntry>();
        using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using RegistryKey? key = baseKey.OpenSubKey(path, writable: false);
        if (key is null) return entries;
        // Enumerate only limit+1 names; do not materialize or sort the complete registry name array.
        foreach (string name in EnumerateValueNames(key, 513))
        {
            token.ThrowIfCancellationRequested();
            if (name.StartsWith("<value-name-limit-", StringComparison.Ordinal))
            {
                const string limitedName = "value-name-limit;sha256=unavailable";
                entries.Add(new(surface, $"{hive}\\{path}\\{name}", limitedName, Hash(surface + "|" + name + "|" + limitedName)));
                continue;
            }
            if (!TryReadBoundedValue(key, name, out string value))
            {
                const string unavailable = "value-size-unavailable;sha256=unavailable";
                entries.Add(new(surface, $"{hive}\\{path}\\{name}", unavailable, Hash(surface + "|" + name + "|" + unavailable)));
                continue;
            }
            entries.Add(new(surface, $"{hive}\\{path}\\{name}", value, Hash(surface + "|" + name + "|" + value)));
        }
        return entries;
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    [SupportedOSPlatform("windows")]
    internal static IEnumerable<string> EnumerateValueNames(RegistryKey key, int limit)
    {
        const int moreData = 234, noMoreItems = 259;
        for (uint index = 0; index < limit; index++)
        {
            var name = new StringBuilder(16 * 1024); uint chars = (uint)name.Capacity;
            uint type = 0, bytes = 0;
            int status = RegEnumValue(key.Handle, index, name, ref chars, IntPtr.Zero, ref type, IntPtr.Zero, ref bytes);
            if (status == noMoreItems) yield break;
            if (status == moreData) { yield return RegistryNameLimitMarker("value", index); yield break; }
            if (status != 0) yield break;
            yield return name.ToString();
        }
    }

    [SupportedOSPlatform("windows")]
    internal static IEnumerable<string> EnumerateSubKeyNames(RegistryKey key, int limit)
    {
        const int moreData = 234, noMoreItems = 259;
        for (uint index = 0; index < limit; index++)
        {
            var name = new StringBuilder(16 * 1024); uint chars = (uint)name.Capacity;
            int status = RegEnumKeyEx(key.Handle, index, name, ref chars, IntPtr.Zero, null, IntPtr.Zero, out _);
            if (status == noMoreItems) yield break;
            if (status == moreData) { yield return RegistryNameLimitMarker("subkey", index); yield break; }
            if (status != 0) yield break;
            yield return name.ToString();
        }
    }

    [SupportedOSPlatform("windows")]
    internal static bool TryReadBoundedValue(RegistryKey key, string name, out string value)
    {
        value = "";
        if (!TryGetValueSize(key, name, out uint size)) return false;
        if (size > 64 * 1024) { value = $"value-limit:length={size};sha256=unavailable"; return true; }
        uint type = 0, actual = size;
        byte[] data = new byte[size];
        int status = RegQueryValueEx(key.Handle, name, IntPtr.Zero, ref type, data, ref actual);
        return TryNormalizeBoundedRegistryRead(size, type, status, actual, data, out value);
    }

    // Kept separate from the registry handle access so regressions can exercise a value that
    // changes size between the metadata query and the read (a normal registry TOCTOU case).
    internal static bool TryNormalizeBoundedRegistryRead(uint queriedSize, uint type, int status, uint actual, byte[] data, out string value)
    {
        const int success = 0;
        const int moreData = 234;
        const uint maxValueBytes = 64 * 1024;
        value = "";
        if (queriedSize > maxValueBytes)
        {
            value = $"value-limit:length={queriedSize};sha256=unavailable";
            return true;
        }
        if (status == moreData || actual > data.Length)
        {
            // Do not retry a growing value: retaining a partial value could be misleading and
            // repeatedly resizing can be abused to consume memory.
            value = $"value-size-unavailable;reason=resize-detected;length={actual};sha256=unavailable";
            return true;
        }
        if (status != success || actual > maxValueBytes) return false;
        if (actual != data.Length) Array.Resize(ref data, (int)actual);
        value = type switch
        {
            1 or 2 => NormalizeText(System.Text.Encoding.Unicode.GetString(data).TrimEnd('\0')),
            7 => NormalizeMultiString(System.Text.Encoding.Unicode.GetString(data).TrimEnd('\0').Split('\0')),
            _ => $"binary:length={data.Length};sha256={Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant()}"
        };
        return true;
    }

    internal static string RegistryNameLimitMarker(string kind, uint index)
    {
        if (kind is not ("value" or "subkey")) throw new ArgumentOutOfRangeException(nameof(kind));
        return $"<{kind}-name-limit-{index}>";
    }

    [SupportedOSPlatform("windows")]
    private static bool TryGetValueSize(RegistryKey key, string name, out uint size)
    {
        size = 0;
        try
        {
            uint type = 0, bytes = 0;
            int status = RegQueryValueEx(key.Handle, name, IntPtr.Zero, ref type, IntPtr.Zero, ref bytes);
            if (status != 0) return false;
            size = bytes; return true;
        }
        catch { return false; }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryValueEx(SafeRegistryHandle hKey, string lpValueName, IntPtr lpReserved, ref uint lpType, IntPtr lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryValueEx(SafeRegistryHandle hKey, string lpValueName, IntPtr lpReserved, ref uint lpType, byte[] lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegEnumValue(SafeRegistryHandle hKey, uint dwIndex, StringBuilder lpValueName, ref uint lpcchValueName, IntPtr lpReserved, ref uint lpType, IntPtr lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegEnumKeyEx(SafeRegistryHandle hKey, uint dwIndex, StringBuilder lpName, ref uint lpcchName, IntPtr lpReserved, StringBuilder? lpClass, IntPtr lpcchClass, out long lpftLastWriteTime);

    internal static string NormalizeRegistryValue(object? value) => value switch
    {
        null => "",
        byte[] bytes => $"binary:length={bytes.Length};sha256={Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}",
        string[] strings => NormalizeMultiString(strings),
        string text => NormalizeText(text),
        _ => NormalizeText(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "")
    };

    private static string NormalizeText(string text)
    {
        const int limit = 4096;
        if (text.Length <= limit) return text;
        return $"value-limit:length={text.Length};sha256={Hash(text)}";
    }

    private static string NormalizeMultiString(string[] values)
    {
        const int elementLimit = 64, charLimit = 4096;
        bool bounded = values.Length > elementLimit || values.Any(v => v.Length > 256);
        if (bounded)
            return $"value-limit:multi-count={values.Length};chars={values.Sum(v => (long)v.Length)};sha256={HashMulti(values)}";
        var preview = new System.Text.StringBuilder("multi-string:", charLimit + 16);
        foreach (string value in values.Take(elementLimit))
        {
            string item = value.Length <= 256 ? value.Replace("|", "\\|", StringComparison.Ordinal) : $"sha256={Hash(value)}";
            if (preview.Length > "multi-string:".Length) preview.Append('|');
            if (preview.Length + item.Length > charLimit) { bounded = true; break; }
            preview.Append(item);
        }
        if (!bounded && preview.Length <= charLimit) return preview.ToString();
        return $"value-limit:multi-count={values.Length};chars={values.Sum(v => (long)v.Length)};sha256={HashMulti(values)}";
    }

    // Hash each element in bounded UTF-8 chunks so a hostile REG_MULTI_SZ cannot force a giant joined string or byte array.
    private static string HashMulti(IEnumerable<string> values)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var utf8 = System.Text.Encoding.UTF8;
        Encoder encoder = utf8.GetEncoder();
        char[] chars = new char[1024]; byte[] bytes = new byte[4096];
        foreach (string value in values)
        {
            int offset = 0;
            while (offset < value.Length)
            {
                int count = Math.Min(chars.Length, value.Length - offset);
                value.CopyTo(offset, chars, 0, count);
                bool flush = offset + count == value.Length;
                encoder.Convert(chars, 0, count, bytes, 0, bytes.Length, flush, out int charsUsed, out int bytesUsed, out _);
                hash.AppendData(bytes, 0, bytesUsed); offset += charsUsed;
            }
            hash.AppendData(NulSeparator); encoder.Reset();
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}
