using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace MRTW.Core;

internal static partial class EvidencePathPolicy
{
    [GeneratedRegex("^[A-Za-z0-9_-]{1,96}$")]
    private static partial Regex SafeId();
    public static string Root(string caseId)
    {
        if (!SafeId().IsMatch(caseId)) throw new InvalidOperationException("Unsafe case identifier.");
        return Path.GetFullPath(Path.Combine(Path.GetTempPath(), "MRTW", caseId));
    }

    public static bool TryValidate(string path, string caseId, long maxBytes, string? expectedHash, out string full, string? trustedRoot = null)
    {
        full = "";
        try
        {
            string root = Path.GetFullPath(string.IsNullOrWhiteSpace(trustedRoot) ? Root(caseId) : trustedRoot) + Path.DirectorySeparatorChar;
            full = Path.GetFullPath(path);
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
            var info = new FileInfo(full);
            if (!info.Exists || info.Length > maxBytes || (info.Attributes & FileAttributes.ReparsePoint) != 0) return false;
            for (DirectoryInfo? d = info.Directory; d is not null; d = d.Parent)
            {
                if ((d.Attributes & FileAttributes.ReparsePoint) != 0) return false;
                if (d.FullName.TrimEnd(Path.DirectorySeparatorChar).Equals(root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)) break;
                if (!d.FullName.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
            }
            if (!string.IsNullOrWhiteSpace(expectedHash))
            {
                using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
                if (!Convert.ToHexString(SHA256.HashData(stream)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) return false;
            }
            return true;
        }
        catch { return false; }
    }

    public static bool CopyValidated(string source, string destination, string caseId, string trustedRoot, string requiredArea, long maxBytes, string expectedHash, out long copied, out string actualHash)
    {
        copied = 0; actualHash = "";
        string root;
        string full;
        try { _ = Root(caseId); root = Path.GetFullPath(trustedRoot); full = Path.GetFullPath(source); } catch { return false; }
        string allowed = Path.GetFullPath(Path.Combine(root, requiredArea)) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(allowed, StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            var info = new FileInfo(full); if (!info.Exists || info.Length > maxBytes || (info.Attributes & FileAttributes.ReparsePoint) != 0) return false;
            string rootWithSlash = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            for (DirectoryInfo? d = info.Directory; d is not null; d = d.Parent) { if ((d.Attributes & FileAttributes.ReparsePoint) != 0) return false; if (d.FullName.Equals(root, StringComparison.OrdinalIgnoreCase)) break; if (!d.FullName.StartsWith(rootWithSlash, StringComparison.OrdinalIgnoreCase)) return false; }
        }
        catch { return false; }
        string temp = destination + ".partial-" + Guid.NewGuid().ToString("N");
        try
        {
            using var input = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            using var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); byte[] buffer = new byte[65536]; int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0) { if (copied + read > maxBytes) throw new InvalidDataException(); output.Write(buffer, 0, read); hash.AppendData(buffer, 0, read); copied += read; }
            output.Flush(true); actualHash = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            output.Dispose(); File.Move(temp, destination, true); return true;
        }
        catch { try { File.Delete(temp); } catch { } return false; }
    }
}
