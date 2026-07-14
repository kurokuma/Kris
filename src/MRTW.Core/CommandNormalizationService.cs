using System.Text;
using System.Text.RegularExpressions;

namespace MRTW.Core;

/// <summary>Pure, bounded textual command analysis. It performs no process, file, COM, archive or network operation.</summary>
public static class CommandNormalizationService
{
    private const int MaxInput = 16 * 1024, MaxDecoded = 32 * 1024;
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly Encoding StrictUtf16Le = new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true);
    private static readonly Regex Encoded = new("(?ix)(?:-(?:enc|encodedcommand)\\s+|frombase64string\\s*\\(\\s*['\\\"]?)([A-Za-z0-9+/=]{4,})", RegexOptions.Compiled);
    private static readonly Regex Lolbin = new(@"(?i)(?:^|[\\/\s])(powershell|pwsh|certutil|rundll32|regsvr32|mshta)(?:\.exe)?(?:\s|$)", RegexOptions.Compiled);
    public static IReadOnlyList<NormalizedCommand> Normalize(string? input, CommandNormalizationBudget? budget = null)
    {
        if (string.IsNullOrWhiteSpace(input)) return [];
        if (budget is not null && !budget.TryConsume(input.Length)) return [];
        if (input.Length > MaxInput) return [new(input[..MaxInput], input[..MaxInput], "", "bounded", "input-limit")];
        string lolbin = Lolbin.Match(input) is { Success: true } lm ? lm.Groups[1].Value.ToLowerInvariant() : "";
        var match = Encoded.Match(input);
        if (!match.Success) return [new(input, input, "", "not-encoded", "", lolbin)];
        string token = match.Groups[1].Value;
        try
        {
            byte[] bytes = Convert.FromBase64String(token);
            if (bytes.Length > MaxDecoded) return [new(input, input, "base64", "bounded", "decoded-limit", lolbin)];
            // EncodedCommand is UTF-16LE; FromBase64String may carry UTF-8. Reject binary/invalid data safely.
            string decoded = input.Contains("-enc", StringComparison.OrdinalIgnoreCase) ? StrictUtf16Le.GetString(bytes) : StrictUtf8.GetString(bytes);
            if (decoded.Any(c => char.IsControl(c) && c is not '\r' and not '\n' and not '\t')) return [new(input, input, "base64", "failed", "binary-or-invalid-text", lolbin)];
            return [new(input, decoded, "base64", "decoded", "", lolbin)];
        }
        catch (FormatException) { return [new(input, input, "base64", "failed", "invalid-base64", lolbin)]; }
        catch (DecoderFallbackException) { return [new(input, input, "base64", "failed", "invalid-text-encoding", lolbin)]; }
    }
}

/// <summary>Case-local work cap for command analysis; callers expose exhaustion as collection quality.</summary>
public sealed class CommandNormalizationBudget
{
    public const int MaxInputs = 2_000, MaxInputBytes = 512 * 1024, MaxFindings = 256;
    private int _inputs, _bytes, _findings;
    public int Dropped { get; private set; }
    public bool Exhausted { get; private set; }
    public bool TryConsume(int inputBytes)
    {
        if (Exhausted || ++_inputs > MaxInputs || inputBytes < 0 || _bytes > MaxInputBytes - inputBytes) { Exhausted = true; Dropped++; return false; }
        _bytes += inputBytes; return true;
    }
    public bool TryAddFinding() { if (_findings >= MaxFindings) { Exhausted = true; Dropped++; return false; } _findings++; return true; }
}
