using MRTW.Core;

namespace MRTW.Collectors.Etw;

public sealed class AnalysisCaseRunner
{
    private readonly StaticAnalysisService _staticAnalysis = new();
    private readonly AnalysisOrchestrator _orchestrator = new();
    private readonly CaseExportService _export = new();

    public CaseData Run(
        ExecutionProfile profile,
        string outputRoot,
        ExportOptions exportOptions,
        string? caseName = null,
        bool overwrite = false,
        bool autoSuffix = false,
        CancellationToken cancellationToken = default,
        Action<TimelineEvent>? onEvent = null,
        Action<NetworkSession>? onNetworkSession = null)
    {
        StaticAnalysisResult? staticResult = File.Exists(profile.TargetPath) ? _staticAnalysis.Analyze(profile.TargetPath) : null;
        CaseData data = _orchestrator.Collect(profile, staticResult, cancellationToken, onEvent, onNetworkSession);
        string directoryName = string.IsNullOrWhiteSpace(caseName) ? data.CaseName : Sanitize(caseName);
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
                directoryName = Path.GetFileName(caseDirectory);
            }
            else
            {
                throw new IOException($"Output directory already exists: {caseDirectory}. Use --overwrite or --auto-suffix.");
            }
        }
        data = data with { CaseName = directoryName };
        _export.WriteCaseBundle(data, caseDirectory, exportOptions);
        return data;
    }

    private static string Sanitize(string value)
    {
        foreach (char invalid in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(invalid, '_');
        }
        return string.IsNullOrWhiteSpace(value) ? "case" : value.Trim();
    }

    private static string NextAvailableDirectory(string outputRoot, string name)
    {
        for (int i = 1; i < 10000; i++)
        {
            string candidate = Path.Combine(outputRoot, $"{name}_{i:D3}");
            if (!Directory.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new IOException("Could not allocate an auto-suffixed case directory.");
    }
}
