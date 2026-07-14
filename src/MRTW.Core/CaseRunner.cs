namespace MRTW.Core;

public sealed class CaseRunner
{
    private readonly StaticAnalysisService _staticAnalysis = new();
    private readonly CaseExportService _export = new();
    private readonly RuntimeCaseCollector _runtime = new();

    public CaseData Run(ExecutionProfile profile, string outputRoot, string formats, string? caseName = null)
    {
        return Run(profile, outputRoot, new ExportOptions(formats), caseName, false, false);
    }

    public CaseData Run(ExecutionProfile profile, string outputRoot, ExportOptions exportOptions, string? caseName = null, bool overwrite = false, bool autoSuffix = false)
    {
        StaticAnalysisResult? staticResult = File.Exists(profile.TargetPath) ? _staticAnalysis.Analyze(profile.TargetPath) : null;
        if (profile.ExecuteTarget)
        {
            ExecutionTargetPolicy.EnsureRunnable(profile, staticResult);
        }
        var data = _runtime.Collect(profile, staticResult);
        string directoryName = string.IsNullOrWhiteSpace(caseName) ? data.CaseName : Sanitize(caseName);
        data = data with { CaseName = directoryName };
        string caseDirectory = Path.Combine(outputRoot, directoryName);
        if (Directory.Exists(caseDirectory))
        {
            if (overwrite)
            {
                Directory.Delete(caseDirectory, true);
            }
            else if (autoSuffix)
            {
                caseDirectory = NextAvailableDirectory(outputRoot, directoryName);
                data = data with { CaseName = Path.GetFileName(caseDirectory) };
            }
            else
            {
                throw new IOException($"Case directory already exists: {caseDirectory}");
            }
        }

        _export.WriteCaseBundle(data, caseDirectory, exportOptions);
        return data;
    }

    public StaticAnalysisResult Static(string targetPath, string outputRoot, string formats, string? caseName = null, bool privacyMode = false)
    {
        var result = _staticAnalysis.Analyze(targetPath);
        var portableResult = privacyMode ? new PrivacyRedactor().Redact(result) : result;
        string directory = Path.Combine(outputRoot, string.IsNullOrWhiteSpace(caseName) ? $"{Path.GetFileName(targetPath)}_{result.Sha256[..8]}_static" : Sanitize(caseName));
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "sample_metadata.json"), System.Text.Json.JsonSerializer.Serialize(portableResult, JsonDefaults.Options));
        File.WriteAllText(Path.Combine(directory, "sections.csv"), "name,virtual_address,raw_size,entropy\r\n" + string.Join("\r\n", portableResult.Sections.Select(s => $"{s.Name},{s.VirtualAddress},{s.RawSize},{s.Entropy}")));
        File.WriteAllText(Path.Combine(directory, "imports.csv"), "name\r\n" + string.Join("\r\n", portableResult.Imports.Select(Csv)));
        File.WriteAllText(Path.Combine(directory, "exports.csv"), "name\r\n" + string.Join("\r\n", portableResult.Exports.Select(Csv)));
        File.WriteAllText(Path.Combine(directory, "strings.csv"), "classification,value\r\n" + string.Join("\r\n", portableResult.SuspiciousStrings.Select(s => $"{Csv(ClassifyString(s))},{Csv(s)}")));
        File.WriteAllText(Path.Combine(directory, "strings.json"), System.Text.Json.JsonSerializer.Serialize(portableResult.SuspiciousStrings, JsonDefaults.Options));
        if (portableResult.NonPeTriage is not null)
        {
            File.WriteAllText(Path.Combine(directory, "initial_access_triage.json"), System.Text.Json.JsonSerializer.Serialize(portableResult.NonPeTriage, JsonDefaults.Options));
            File.WriteAllText(Path.Combine(directory, "initial_access_triage.csv"), "category,value\r\n" + string.Join("\r\n",
                portableResult.NonPeTriage.Indicators.Select(x => $"indicator,{Csv(x)}")
                .Concat(portableResult.NonPeTriage.UrlCandidates.Select(x => $"url,{Csv(x)}"))
                .Concat(portableResult.NonPeTriage.CommandCandidates.Select(x => $"command,{Csv(x)}"))
                .Concat(portableResult.NonPeTriage.EncodedContentMarkers.Select(x => $"encoded_marker,{Csv(x)}"))
                .Concat(portableResult.NonPeTriage.ContainerEntries.Select(x => $"entry,{Csv(x)}"))
                .Concat(portableResult.NonPeTriage.SafetyWarnings.Select(x => $"warning,{Csv(x)}"))));
        }
        if (formats.Contains("html", StringComparison.OrdinalIgnoreCase) || formats.Contains("all", StringComparison.OrdinalIgnoreCase))
        {
            var data = DemoCaseFactory.Create(targetPath, portableResult, 0);
            new CaseExportService().WriteCaseBundle(data, directory, new ExportOptions(formats, PrivacyMode: privacyMode));
            File.Move(Path.Combine(directory, "report.html"), Path.Combine(directory, "static_report.html"), true);
        }
        return result;
    }

    private static string Sanitize(string value)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(c, '_');
        }
        return value;
    }

    private static string Csv(string value) { if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@') value = "'" + value; return "\"" + value.Replace("\"", "\"\"") + "\""; }

    private static string ClassifyString(string value)
    {
        if (value.Contains("http://", StringComparison.OrdinalIgnoreCase) || value.Contains("https://", StringComparison.OrdinalIgnoreCase))
        {
            return "URL";
        }

        if (value.StartsWith("HK", StringComparison.OrdinalIgnoreCase))
        {
            return "Registry";
        }

        if (value.Contains(@":\", StringComparison.Ordinal))
        {
            return "FilePath";
        }

        if (value.Contains("powershell", StringComparison.OrdinalIgnoreCase) || value.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase))
        {
            return "Command";
        }

        return "General";
    }

    private static string NextAvailableDirectory(string outputRoot, string directoryName)
    {
        for (int i = 1; i < 1000; i++)
        {
            string candidate = Path.Combine(outputRoot, $"{directoryName}_{i:000}");
            if (!Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException($"Could not allocate a unique case directory for {directoryName}.");
    }
}
