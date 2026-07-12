using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;

namespace MRTW.Core;

public sealed class StaticAnalysisService
{
    private static readonly Regex InterestingStringPattern = new(
        @"(https?://[^\s""']+|[A-Za-z]:\\[^\r\n\t""']+|HK(CU|LM|CR|U|CC)\\[^\r\n\t""']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|powershell[^\r\n]*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public StaticAnalysisResult Analyze(string path, int minStringLength = 5)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Target file was not found.", path);
        }

        byte[] data = File.ReadAllBytes(path);
        using var md5 = MD5.Create();
        using var sha1 = SHA1.Create();
        using var sha256 = SHA256.Create();

        var pe = TryReadPe(data);
        var strings = ExtractStrings(data, minStringLength)
            .Where(s => InterestingStringPattern.IsMatch(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .ToArray();

        var signature = ReadSignature(path, pe);
        var version = ReadVersionInfo(path);
        var packer = DetectPackerIndicators(pe.Sections, pe.Imports, pe.EntryPoint);
        var embedded = FindEmbeddedPeFiles(data);
        return new StaticAnalysisResult(
            Path.GetFileName(path),
            Path.GetFullPath(path),
            data.LongLength,
            Convert.ToHexString(md5.ComputeHash(data)).ToLowerInvariant(),
            Convert.ToHexString(sha1.ComputeHash(data)).ToLowerInvariant(),
            Convert.ToHexString(sha256.ComputeHash(data)).ToLowerInvariant(),
            pe.IsPe ? "PE executable" : "Binary/data",
            pe.Architecture,
            pe.Timestamp,
            pe.EntryPoint,
            pe.Imports,
            pe.Exports,
            pe.Sections,
            strings,
            data.AsSpan().IndexOf(Encoding.ASCII.GetBytes("BSJB")) >= 0,
            pe.HasCertificate,
            pe.OverlaySize,
            pe.Subsystem,
            pe.ImageBase,
            pe.Resources,
            pe.TlsCallbacks,
            pe.PdbPath,
            signature.Status,
            signature.Subject,
            ComputeImphash(pe.Imports),
            ReadRichHeaderHash(data),
            ReadManifest(data),
            version,
            ReadDotNetMetadata(path, data),
            packer,
            embedded);
    }

    private static IEnumerable<string> ExtractStrings(byte[] data, int minLength)
    {
        var current = new StringBuilder();
        foreach (byte b in data)
        {
            if (b is >= 32 and <= 126)
            {
                current.Append((char)b);
            }
            else
            {
                if (current.Length >= minLength)
                {
                    yield return current.ToString();
                }
                current.Clear();
            }
        }

        if (current.Length >= minLength)
        {
            yield return current.ToString();
        }

        current.Clear();
        for (int i = 0; i + 1 < data.Length; i += 2)
        {
            ushort ch = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(i, 2));
            if (ch is >= 32 and <= 126)
            {
                current.Append((char)ch);
            }
            else
            {
                if (current.Length >= minLength)
                {
                    yield return current.ToString();
                }
                current.Clear();
            }
        }
    }

    private static PeReadResult TryReadPe(byte[] data)
    {
        try
        {
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
            {
                return PeReadResult.NotPe;
            }

            int peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3C, 4));
            if (peOffset < 0 || peOffset + 0x108 >= data.Length || data[peOffset] != 'P' || data[peOffset + 1] != 'E')
            {
                return PeReadResult.NotPe;
            }

            ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(peOffset + 4, 2));
            ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(peOffset + 6, 2));
            uint timestamp = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(peOffset + 8, 4));
            ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(peOffset + 20, 2));
            int optionalOffset = peOffset + 24;
            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(optionalOffset, 2));
            bool pe32Plus = magic == 0x20B;
            uint entryRva = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(optionalOffset + 16, 4));
            ulong imageBase = pe32Plus
                ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(optionalOffset + 24, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(optionalOffset + 28, 4));
            ushort subsystemValue = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(optionalOffset + 68, 2));
            string subsystem = SubsystemName(subsystemValue);
            int dataDirectoryOffset = optionalOffset + (pe32Plus ? 0x70 : 0x60);
            var directories = ReadDataDirectories(data, dataDirectoryOffset);
            int certificateDirectoryOffset = optionalOffset + (pe32Plus ? 0x90 : 0x80);
            uint certificateSize = 0;
            if (certificateDirectoryOffset + 8 <= data.Length)
            {
                certificateSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(certificateDirectoryOffset + 4, 4));
            }
            string entryPoint = $"0x{entryRva:X8}";
            var sections = new List<PeSectionInfo>();
            var sectionHeaders = new List<SectionHeader>();
            int sectionOffset = optionalOffset + optionalSize;
            uint maxRawEnd = 0;

            for (int i = 0; i < sectionCount && sectionOffset + 40 <= data.Length; i++, sectionOffset += 40)
            {
                string name = Encoding.ASCII.GetString(data, sectionOffset, 8).TrimEnd('\0');
                uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(sectionOffset + 12, 4));
                uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(sectionOffset + 16, 4));
                uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(sectionOffset + 20, 4));
                double entropy = 0;
                if (rawPointer < data.Length && rawSize > 0)
                {
                    int count = (int)Math.Min(rawSize, data.Length - rawPointer);
                    entropy = CalculateEntropy(data.AsSpan((int)rawPointer, count));
                    maxRawEnd = Math.Max(maxRawEnd, rawPointer + (uint)count);
                }

                uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(sectionOffset + 8, 4));
                uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(sectionOffset + 36, 4));
                sections.Add(new PeSectionInfo(name, virtualAddress, rawSize, Math.Round(entropy, 2), virtualSize, $"0x{characteristics:X8}"));
                sectionHeaders.Add(new SectionHeader(name, virtualAddress, virtualSize, rawPointer, rawSize));
            }

            string architecture = machine switch
            {
                0x8664 => "x64",
                0x14C => "x86",
                0xAA64 => "ARM64",
                _ => $"0x{machine:X4}"
            };

            var peDate = DateTimeOffset.FromUnixTimeSeconds(timestamp);
            long overlaySize = maxRawEnd > 0 && maxRawEnd < data.Length ? data.Length - maxRawEnd : 0;
            var ascii = Encoding.ASCII.GetString(data);
            var imports = ReadImports(data, directories, sectionHeaders, pe32Plus).Concat(ReadDelayImports(data, directories, sectionHeaders, pe32Plus)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var exports = ReadExports(data, directories, sectionHeaders);
            var resources = ReadResources(data, directories, sectionHeaders);
            var tlsCallbacks = ReadTlsCallbacks(data, directories, sectionHeaders, imageBase, pe32Plus);
            string pdbPath = Regex.Match(ascii, @"[A-Za-z]:\\[^\0\r\n]+?\.pdb", RegexOptions.IgnoreCase).Value;

            return new PeReadResult(
                true,
                architecture + (pe32Plus ? " PE32+" : " PE32"),
                peDate,
                entryPoint,
                imports,
                exports,
                sections,
                overlaySize,
                certificateSize > 0,
                subsystem,
                imageBase,
                resources,
                tlsCallbacks,
                pdbPath);
        }
        catch
        {
            return PeReadResult.NotPe;
        }
    }

    private static double CalculateEntropy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (byte b in bytes)
        {
            counts[b]++;
        }

        double entropy = 0;
        foreach (int count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            double p = (double)count / bytes.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private sealed record PeReadResult(
        bool IsPe,
        string Architecture,
        DateTimeOffset? Timestamp,
        string EntryPoint,
        IReadOnlyList<string> Imports,
        IReadOnlyList<string> Exports,
        IReadOnlyList<PeSectionInfo> Sections,
        long OverlaySize,
        bool HasCertificate,
        string Subsystem,
        ulong ImageBase,
        IReadOnlyList<string> Resources,
        IReadOnlyList<string> TlsCallbacks,
        string PdbPath)
    {
        public static PeReadResult NotPe { get; } = new(false, "Unknown", null, "-", Array.Empty<string>(), Array.Empty<string>(), Array.Empty<PeSectionInfo>(), 0, false, "", 0, Array.Empty<string>(), Array.Empty<string>(), "");
    }

    private static bool DetectAuthenticode(byte[] data, PeReadResult pe) => pe.HasCertificate || data.AsSpan().IndexOf(Encoding.ASCII.GetBytes("WIN_CERTIFICATE")) >= 0;

    private sealed record SectionHeader(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize);

    private sealed record DataDirectory(uint Rva, uint Size);

    private static IReadOnlyList<DataDirectory> ReadDataDirectories(byte[] data, int offset)
    {
        var directories = new List<DataDirectory>();
        for (int i = 0; i < 16 && offset + (i * 8) + 8 <= data.Length; i++)
        {
            int entry = offset + i * 8;
            directories.Add(new DataDirectory(
                BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(entry, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(entry + 4, 4))));
        }

        return directories;
    }

    private static int RvaToOffset(uint rva, IReadOnlyList<SectionHeader> sections)
    {
        foreach (var section in sections)
        {
            uint span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + span)
            {
                return (int)(section.RawPointer + (rva - section.VirtualAddress));
            }
        }

        return (int)rva;
    }

    private static string ReadAsciiZ(byte[] data, int offset, int max = 512)
    {
        if (offset < 0 || offset >= data.Length)
        {
            return string.Empty;
        }

        int end = offset;
        while (end < data.Length && end - offset < max && data[end] != 0)
        {
            end++;
        }

        return end > offset ? Encoding.ASCII.GetString(data, offset, end - offset) : string.Empty;
    }

    private static IReadOnlyList<string> ReadExports(byte[] data, IReadOnlyList<DataDirectory> directories, IReadOnlyList<SectionHeader> sections)
    {
        if (directories.Count == 0 || directories[0].Rva == 0)
        {
            return Array.Empty<string>();
        }

        try
        {
            int exportOffset = RvaToOffset(directories[0].Rva, sections);
            if (exportOffset < 0 || exportOffset + 40 > data.Length)
            {
                return Array.Empty<string>();
            }

            uint numberOfNames = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(exportOffset + 24, 4));
            uint addressOfNames = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(exportOffset + 32, 4));
            int namesOffset = RvaToOffset(addressOfNames, sections);
            var exports = new List<string>();
            for (int i = 0; i < numberOfNames && i < 4096 && namesOffset + (i * 4) + 4 <= data.Length; i++)
            {
                uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(namesOffset + i * 4, 4));
                string name = ReadAsciiZ(data, RvaToOffset(nameRva, sections));
                if (!string.IsNullOrWhiteSpace(name))
                {
                    exports.Add(name);
                }
            }

            return exports.Distinct(StringComparer.OrdinalIgnoreCase).Take(256).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IReadOnlyList<string> ReadImports(byte[] data, IReadOnlyList<DataDirectory> directories, IReadOnlyList<SectionHeader> sections, bool pe32Plus)
    {
        if (directories.Count <= 1 || directories[1].Rva == 0) return Array.Empty<string>();
        var result = new List<string>();
        try
        {
            int descriptor = RvaToOffset(directories[1].Rva, sections);
            int pointerSize = pe32Plus ? 8 : 4;
            for (int d = 0; d < 512 && descriptor + d * 20 + 20 <= data.Length; d++)
            {
                int p = descriptor + d * 20;
                uint lookupRva = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p, 4));
                uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 12, 4));
                uint iatRva = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 16, 4));
                if (lookupRva == 0 && nameRva == 0 && iatRva == 0) break;
                string dll = ReadAsciiZ(data, RvaToOffset(nameRva, sections), 260);
                if (string.IsNullOrWhiteSpace(dll)) continue;
                int lookup = RvaToOffset(lookupRva == 0 ? iatRva : lookupRva, sections);
                for (int i = 0; i < 8192 && lookup + i * pointerSize + pointerSize <= data.Length; i++)
                {
                    ulong thunk = pe32Plus
                        ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(lookup + i * pointerSize, 8))
                        : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(lookup + i * pointerSize, 4));
                    if (thunk == 0) break;
                    ulong ordinalMask = pe32Plus ? 0x8000000000000000UL : 0x80000000UL;
                    string function = (thunk & ordinalMask) != 0
                        ? $"ord{thunk & 0xffff}"
                        : ReadAsciiZ(data, RvaToOffset((uint)thunk, sections) + 2, 512);
                    result.Add($"{dll}!{(string.IsNullOrWhiteSpace(function) ? "?" : function)}");
                }
            }
        }
        catch { }
        return result.Distinct(StringComparer.OrdinalIgnoreCase).Take(8192).ToArray();
    }

    private static IReadOnlyList<string> ReadDelayImports(byte[] data, IReadOnlyList<DataDirectory> directories, IReadOnlyList<SectionHeader> sections, bool pe32Plus)
    {
        if (directories.Count <= 13 || directories[13].Rva == 0) return [];
        var result = new List<string>();
        try
        {
            int root = RvaToOffset(directories[13].Rva, sections); int pointerSize = pe32Plus ? 8 : 4;
            for (int d = 0; d < 256 && root + d * 32 + 32 <= data.Length; d++)
            {
                int p = root + d * 32; uint attrs = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p, 4)); uint name = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 4, 4)); uint table = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 16, 4));
                if (name == 0 && table == 0) break; if ((attrs & 1) == 0) continue;
                string dll = ReadAsciiZ(data, RvaToOffset(name, sections), 260); int lookup = RvaToOffset(table, sections);
                for (int i = 0; i < 4096 && lookup + i * pointerSize + pointerSize <= data.Length; i++)
                {
                    ulong thunk = pe32Plus ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(lookup + i * pointerSize, 8)) : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(lookup + i * pointerSize, 4)); if (thunk == 0) break;
                    ulong mask = pe32Plus ? 0x8000000000000000UL : 0x80000000UL; string fn = (thunk & mask) != 0 ? $"ord{thunk & 0xffff}" : ReadAsciiZ(data, RvaToOffset((uint)thunk, sections) + 2, 512);
                    result.Add($"{dll}!{fn} [delay]");
                }
            }
        }
        catch { }
        return result;
    }

    private static string ComputeImphash(IReadOnlyList<string> imports)
    {
        if (imports.Count == 0) return "";
        string canonical = string.Join(',', imports.Select(i => i.ToLowerInvariant().Replace(".dll!", "!")));
        return Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static (string Status, string Subject) ReadSignature(string path, PeReadResult pe)
    {
        if (!pe.HasCertificate) return ("Not signed", "");
        if (!OperatingSystem.IsWindows()) return ("Present (not validated on this platform)", "");
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            int policy = WinTrustPolicy.Verify(path);
            return (policy == 0 ? "Valid" : $"Signed (WinVerifyTrust 0x{policy:X8})", cert.Subject);
        }
        catch (Exception ex) { return ($"Malformed/unreadable signature: {ex.GetType().Name}", ""); }
    }

    private static IReadOnlyDictionary<string, string> ReadVersionInfo(string path)
    {
        try
        {
            var v = FileVersionInfo.GetVersionInfo(path);
            return new Dictionary<string, string> { ["Company"] = v.CompanyName ?? "", ["Description"] = v.FileDescription ?? "", ["FileVersion"] = v.FileVersion ?? "", ["Product"] = v.ProductName ?? "", ["ProductVersion"] = v.ProductVersion ?? "", ["OriginalFilename"] = v.OriginalFilename ?? "" };
        }
        catch { return new Dictionary<string, string>(); }
    }

    private static string ReadRichHeaderHash(byte[] data)
    {
        int rich = data.AsSpan().IndexOf("Rich"u8);
        if (rich < 0) return "";
        int start = data.AsSpan(0, rich).LastIndexOf("DanS"u8);
        if (start < 0) start = Math.Max(0, rich - 256);
        return Convert.ToHexString(SHA256.HashData(data.AsSpan(start, rich + 8 <= data.Length ? rich + 8 - start : rich + 4 - start))).ToLowerInvariant();
    }

    private static string ReadManifest(byte[] data)
    {
        string text = Encoding.UTF8.GetString(data);
        int start = text.IndexOf("<assembly", StringComparison.OrdinalIgnoreCase);
        if (start < 0) return "";
        int end = text.IndexOf("</assembly>", start, StringComparison.OrdinalIgnoreCase);
        return end < 0 ? "" : text.Substring(start, Math.Min(end + 11 - start, 32768));
    }

    private static IReadOnlyList<string> ReadDotNetMetadata(string path, byte[] data)
    {
        if (data.AsSpan().IndexOf("BSJB"u8) < 0) return Array.Empty<string>();
        var found = new List<string> { ".NET metadata signature present" };
        try
        {
            using var stream = File.OpenRead(path); using var pe = new PEReader(stream);
            if (!pe.HasMetadata) return found;
            MetadataReader metadata = pe.GetMetadataReader();
            foreach (var handle in metadata.AssemblyReferences.Take(100)) { var reference = metadata.GetAssemblyReference(handle); found.Add("AssemblyRef: " + metadata.GetString(reference.Name)); }
            foreach (var handle in metadata.TypeDefinitions.Take(500)) { var type = metadata.GetTypeDefinition(handle); found.Add("Type: " + metadata.GetString(type.Namespace) + "." + metadata.GetString(type.Name)); }
            foreach (var handle in metadata.MethodDefinitions.Take(1000)) { var method = metadata.GetMethodDefinition(handle); found.Add("Method: " + metadata.GetString(method.Name)); }
        }
        catch { }
        return found.Distinct().Take(1600).ToArray();
    }

    private static IReadOnlyList<string> DetectPackerIndicators(IReadOnlyList<PeSectionInfo> sections, IReadOnlyList<string> imports, string entryPoint)
    {
        var indicators = new List<string>();
        foreach (var s in sections)
        {
            if (s.Entropy >= 7.2) indicators.Add($"High entropy section {s.Name}: {s.Entropy:F2}");
            if (Regex.IsMatch(s.Name, @"^(UPX|\.aspack|\.adata|MPRESS|Themida)", RegexOptions.IgnoreCase)) indicators.Add($"Known packer-like section name: {s.Name}");
        }
        if (imports.Count is > 0 and < 8) indicators.Add($"Very small import table: {imports.Count} entries");
        return indicators.Take(50).ToArray();
    }

    private static IReadOnlyList<EmbeddedPeInfo> FindEmbeddedPeFiles(byte[] data)
    {
        var result = new List<EmbeddedPeInfo>();
        const int maxHits = 16;
        for (int i = 1; i + 0x40 < data.Length && result.Count < maxHits; i++)
        {
            if (data[i] != 'M' || data[i + 1] != 'Z') continue;
            int peOffset;
            try { peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(i + 0x3c, 4)); } catch { continue; }
            if (peOffset < 0x40 || i + peOffset + 6 >= data.Length || data[i + peOffset] != 'P' || data[i + peOffset + 1] != 'E') continue;
            int size = EmbeddedImageSize(data, i, peOffset);
            if (size <= 0) continue;
            ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(i + peOffset + 4, 2));
            result.Add(new EmbeddedPeInfo(i, machine == 0x8664 ? "x64" : machine == 0x14c ? "x86" : $"0x{machine:X4}", Convert.ToHexString(SHA256.HashData(data.AsSpan(i, size))).ToLowerInvariant(), size));
            i += 63;
        }
        return result;
    }

    private static int EmbeddedImageSize(byte[] data, int origin, int peOffset)
    {
        try
        {
            int header = origin + peOffset; ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(header + 6, 2)); ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(header + 20, 2)); int optional = header + 24; ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(optional, 2));
            int section = optional + optionalSize; long end = section + sectionCount * 40L;
            for (int s = 0; s < sectionCount && section + s * 40 + 40 <= data.Length; s++) { int p = section + s * 40; uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 16, 4)); uint rawPtr = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 20, 4)); end = Math.Max(end, rawPtr + (long)rawSize); }
            int certDir = optional + (magic == 0x20b ? 0x90 : 0x80); if (certDir + 8 <= data.Length) { uint certOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(certDir, 4)); uint certSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(certDir + 4, 4)); end = Math.Max(end, certOffset + (long)certSize); }
            if (end <= 0 || end > 16 * 1024 * 1024 || origin + end > data.Length) return 0;
            return (int)end;
        }
        catch { return 0; }
    }

    private static IReadOnlyList<string> ReadResources(byte[] data, IReadOnlyList<DataDirectory> directories, IReadOnlyList<SectionHeader> sections)
    {
        if (directories.Count <= 2 || directories[2].Rva == 0)
        {
            return Array.Empty<string>();
        }

        try
        {
            int root = RvaToOffset(directories[2].Rva, sections);
            if (root < 0 || root + 16 > data.Length)
            {
                return Array.Empty<string>();
            }

            ushort named = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(root + 12, 2));
            ushort ids = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(root + 14, 2));
            int count = named + ids;
            var resources = new List<string>();
            for (int i = 0; i < count && i < 128 && root + 16 + i * 8 + 8 <= data.Length; i++)
            {
                uint nameOrId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(root + 16 + i * 8, 4));
                resources.Add(ResourceTypeName(nameOrId & 0x7FFFFFFF));
            }

            return resources.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IReadOnlyList<string> ReadTlsCallbacks(byte[] data, IReadOnlyList<DataDirectory> directories, IReadOnlyList<SectionHeader> sections, ulong imageBase, bool pe32Plus)
    {
        if (directories.Count <= 9 || directories[9].Rva == 0)
        {
            return Array.Empty<string>();
        }

        try
        {
            int tlsOffset = RvaToOffset(directories[9].Rva, sections);
            int callbackFieldOffset = tlsOffset + (pe32Plus ? 24 : 12);
            if (callbackFieldOffset + (pe32Plus ? 8 : 4) > data.Length)
            {
                return Array.Empty<string>();
            }

            ulong callbacksVa = pe32Plus
                ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(callbackFieldOffset, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(callbackFieldOffset, 4));
            if (callbacksVa == 0 || callbacksVa < imageBase)
            {
                return Array.Empty<string>();
            }

            int callbacksOffset = RvaToOffset((uint)(callbacksVa - imageBase), sections);
            var callbacks = new List<string>();
            int pointerSize = pe32Plus ? 8 : 4;
            for (int i = 0; i < 64 && callbacksOffset + i * pointerSize + pointerSize <= data.Length; i++)
            {
                ulong callbackVa = pe32Plus
                    ? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(callbacksOffset + i * pointerSize, pointerSize))
                    : BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(callbacksOffset + i * pointerSize, pointerSize));
                if (callbackVa == 0)
                {
                    break;
                }

                callbacks.Add($"0x{callbackVa:X}");
            }

            return callbacks.ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string SubsystemName(ushort value) => value switch
    {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        7 => "POSIX CUI",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        _ => value == 0 ? "" : $"Unknown ({value})"
    };

    private static string ResourceTypeName(uint value) => value switch
    {
        1 => "Cursor",
        2 => "Bitmap",
        3 => "Icon",
        4 => "Menu",
        5 => "Dialog",
        6 => "String",
        7 => "FontDirectory",
        8 => "Font",
        9 => "Accelerator",
        10 => "RcData",
        11 => "MessageTable",
        12 => "GroupCursor",
        14 => "GroupIcon",
        16 => "Version",
        24 => "Manifest",
        _ => $"ResourceId:{value}"
    };

    private static class WinTrustPolicy
    {
        private const uint WtdUiNone = 2, WtdRevokeWholeChain = 1, WtdChoiceFile = 1, WtdStateActionVerify = 1, WtdStateActionClose = 2, WtdCacheOnlyUrlRetrieval = 0x1000;
        private static readonly Guid Action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct FileInfo { public uint Size; public IntPtr Path; public IntPtr File; public IntPtr KnownSubject; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct TrustData { public uint Size; public IntPtr PolicyCallbackData; public IntPtr SipClientData; public uint UiChoice; public uint RevocationChecks; public uint UnionChoice; public IntPtr FileInfo; public uint StateAction; public IntPtr StateData; public IntPtr UrlReference; public uint ProviderFlags; public uint UiContext; public IntPtr SignatureSettings; }
        public static int Verify(string path)
        {
            if (!OperatingSystem.IsWindows()) return unchecked((int)0x800B0100);
            IntPtr pathPtr = IntPtr.Zero, filePtr = IntPtr.Zero, dataPtr = IntPtr.Zero;
            try
            {
                pathPtr = Marshal.StringToCoTaskMemUni(path);
                var file = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = pathPtr };
                filePtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<FileInfo>()); Marshal.StructureToPtr(file, filePtr, false);
                var trust = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = WtdUiNone, RevocationChecks = WtdRevokeWholeChain, UnionChoice = WtdChoiceFile, FileInfo = filePtr, StateAction = WtdStateActionVerify, ProviderFlags = WtdCacheOnlyUrlRetrieval };
                dataPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<TrustData>()); Marshal.StructureToPtr(trust, dataPtr, false);
                int result = WinVerifyTrust(new IntPtr(-1), Action, dataPtr);
                trust.StateAction = WtdStateActionClose; Marshal.StructureToPtr(trust, dataPtr, true); WinVerifyTrust(new IntPtr(-1), Action, dataPtr);
                return result;
            }
            finally { if (dataPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(dataPtr); if (filePtr != IntPtr.Zero) Marshal.FreeCoTaskMem(filePtr); if (pathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPtr); }
        }
    }
}
