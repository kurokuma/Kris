using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace MRTW.Core;

/// <summary>
/// Deliberately small, read-only non-PE triage.  It does not invoke COM, MSI APIs,
/// shell/link resolution, decompression to disk, or encoded-content decoding.
/// </summary>
internal static class NonPeTriageService
{
    private const int MaxEntries = 256;
    private const long MaxEntryBytes = 16L * 1024 * 1024;
    private const long MaxTotalBytes = 64L * 1024 * 1024;
    private const double MaxCompressionRatio = 100d;
    private static readonly Regex Url = new(@"https?://[^\s\""'<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Command = new(@"(?im)^\s*(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?)[^\r\n]{0,1024}", RegexOptions.Compiled);
    private static readonly Regex LnkCommand = new(@"(?i)(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?)[^\r\n]{0,1024}", RegexOptions.Compiled);
    private static readonly Regex Encoded = new(@"(?i)(?:-enc(?:odedcommand)?\b|frombase64string\s*\(|base64\b)", RegexOptions.Compiled);

    public static NonPeTriageResult Analyze(string path, byte[] data)
    {
        string extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is ".zip" or ".docx" or ".xlsx" or ".pptx" || IsZip(data))
            return AnalyzeZip(extension, data);
        if (IsCompoundFile(data)) return AnalyzeCompound(extension, data);
        if (extension == ".lnk") return AnalyzeLnk(data);
        if (extension is ".ps1" or ".psm1" or ".js" or ".jse" or ".vbs" or ".vbe" or ".wsf") return AnalyzeScript(extension, data);
        return Empty("Binary/data", "Unsupported non-PE format; retained only as a bounded binary first look.");
    }

    private static NonPeTriageResult AnalyzeScript(string extension, byte[] data)
    {
        string text = ReadBoundedText(data);
        return new NonPeTriageResult($"Script ({extension.TrimStart('.').ToUpperInvariant()})", false,
            ["Script content was inspected as text only; it was not executed or decoded."],
            Values(Url.Matches(text).Select(m => m.Value)), Values(Command.Matches(text).Select(m => m.Value.Trim())),
            Values(Encoded.Matches(text).Select(m => m.Value)), [], []);
    }

    private static NonPeTriageResult AnalyzeLnk(byte[] data)
    {
        // LNK LinkInfo/StringData is intentionally not resolved. Printable candidates are evidence only.
        string text = ReadBoundedLnkText(data);
        var indicators = new List<string> { "Shortcut was not resolved or invoked." };
        if (data.Length >= 4 && BitConverter.ToUInt32(data, 0) == 0x4C) indicators.Add("Shell Link header present.");
        return new NonPeTriageResult("Windows Shortcut (LNK)", false, indicators,
            Values(Url.Matches(text).Select(m => m.Value)), Values(LnkCommand.Matches(text).Select(m => m.Value.Trim())), [], [], []);
    }

    private static NonPeTriageResult AnalyzeCompound(string extension, byte[] data)
    {
        string format = extension == ".msi" ? "Windows Installer database (MSI/CFBF)" :
            extension is ".doc" or ".xls" or ".ppt" ? "Legacy Office document (CFBF)" : "Compound File Binary Format (CFBF)";
        return new NonPeTriageResult(format, false,
            ["Compound container identified from its signature.", "COM, Windows Installer, and Office automation were not used."], [], [], [], [], []);
    }

    private static NonPeTriageResult AnalyzeZip(string extension, byte[] data)
    {
        var entries = new List<string>(); var warnings = new List<string>(); var indicators = new List<string>();
        string format = extension switch { ".docx" => "Office Open XML Word document", ".xlsx" => "Office Open XML Excel workbook", ".pptx" => "Office Open XML PowerPoint presentation", _ => "ZIP archive" };
        try
        {
            if (HasEncryptedZipEntry(data)) warnings.Add("Encrypted ZIP entry detected; encrypted content was not opened.");
            using var stream = new MemoryStream(data, writable: false);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
            indicators.Add("Container inspected in memory; entries were not extracted to disk.");
            if (archive.Entries.Count > MaxEntries) warnings.Add($"Entry count exceeds limit ({MaxEntries}); remaining entries were not analyzed.");
            long total = 0;
            foreach (var entry in archive.Entries.Take(MaxEntries))
            {
                if (IsUnsafeEntry(entry.FullName)) { warnings.Add($"Unsafe entry path ignored: {entry.FullName}"); continue; }
                if (entry.Length > MaxEntryBytes) { warnings.Add($"Oversized entry ignored: {entry.FullName}"); continue; }
                if (entry.CompressedLength > 0 && entry.Length / (double)entry.CompressedLength > MaxCompressionRatio) { warnings.Add($"High compression ratio entry ignored: {entry.FullName}"); continue; }
                if (total > MaxTotalBytes - entry.Length) { warnings.Add("Total inspected entry size limit reached."); break; }
                total += entry.Length;
                entries.Add($"{entry.FullName} ({entry.Length} bytes)");
                if (entry.FullName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) || entry.FullName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase) || entry.FullName.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase) || entry.FullName.EndsWith(".pptx", StringComparison.OrdinalIgnoreCase))
                    warnings.Add($"Nested container not opened: {entry.FullName}");
            }
            if (entries.Any(e => e.StartsWith("[Content_Types].xml", StringComparison.OrdinalIgnoreCase))) indicators.Add("OOXML content-types manifest present.");
        }
        catch (InvalidDataException) { warnings.Add("Malformed or encrypted ZIP container could not be inspected."); }
        return new NonPeTriageResult(format, false, indicators, [], [], [], entries, warnings);
    }

    private static bool IsZip(byte[] value) => value.Length >= 4 && value[0] == (byte)'P' && value[1] == (byte)'K' && (value[2] == 3 || value[2] == 5 || value[2] == 7);
    private static bool HasEncryptedZipEntry(byte[] value)
    {
        // General-purpose flag bit 0 in each local file header. Scan only a bounded prefix.
        for (int i = 0, end = Math.Min(value.Length - 8, 1024 * 1024); i < end; i++)
            if (value[i] == (byte)'P' && value[i + 1] == (byte)'K' && value[i + 2] == 3 && value[i + 3] == 4 && (value[i + 6] & 1) != 0) return true;
        return false;
    }
    private static bool IsCompoundFile(byte[] value) => value.Length >= 8 && value.AsSpan(0, 8).SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
    private static bool IsUnsafeEntry(string name) => string.IsNullOrWhiteSpace(name) || Path.IsPathRooted(name) || name.Contains("..", StringComparison.Ordinal) || name.Contains(':');
    private static string ReadBoundedText(byte[] data) => Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 256 * 1024));
    private static string ReadBoundedLnkText(byte[] data)
    {
        int byteCount = Math.Min(data.Length, 256 * 1024) & ~1;
        // Both decodings are evidence-only and bounded. NULs are normalized so StringData candidates
        // can be matched without resolving the shortcut.
        return ReadBoundedText(data) + "\n" + Encoding.Unicode.GetString(data, 0, byteCount).Replace('\0', ' ');
    }
    private static IReadOnlyList<string> Values(IEnumerable<string> values) => values.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToArray();
    private static NonPeTriageResult Empty(string format, string warning) => new(format, false, [], [], [], [], [], [warning]);
}
