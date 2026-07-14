using System.Buffers.Binary;

namespace MRTW.Core;

/// <summary>Final Core boundary for executable targets. UI/CLI validation is advisory; this is authoritative.</summary>
internal static class ExecutionTargetPolicy
{
    internal const string Rejection = "Execution skipped: runtime analysis accepts only validated PE EXE/DLL targets. Use static analysis for non-PE targets.";

    internal static void EnsureRunnable(ExecutionProfile profile, StaticAnalysisResult? staticAnalysis)
    {
        if (profile.TargetType.Equals("command", StringComparison.OrdinalIgnoreCase))
        {
            // `--cmd` without a target uses the synthetic command.exe placeholder and remains supported.
            // A real supplied target is still a launch boundary and must be an actual PE.
            if (staticAnalysis?.NonPeTriage is not null || (File.Exists(profile.TargetPath) && !IsPeImage(profile.TargetPath)))
                throw new InvalidOperationException(Rejection);
            return;
        }
        if (!profile.TargetType.Equals("exe", StringComparison.OrdinalIgnoreCase) && !profile.TargetType.Equals("dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(Rejection);
        if (staticAnalysis?.NonPeTriage is not null || !IsPeImage(profile.TargetPath))
            throw new InvalidOperationException(Rejection);
    }

    internal static bool IsPeImage(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 512, FileOptions.SequentialScan);
            Span<byte> header = stackalloc byte[64];
            if (stream.Read(header) != header.Length || header[0] != (byte)'M' || header[1] != (byte)'Z') return false;
            int offset = BinaryPrimitives.ReadInt32LittleEndian(header[0x3c..]);
            if (offset < 0x40 || offset > 1024 * 1024) return false;
            stream.Position = offset;
            Span<byte> signature = stackalloc byte[4];
            return stream.Read(signature) == signature.Length && signature.SequenceEqual("PE\0\0"u8);
        }
        catch { return false; }
    }
}
