using System.Net;
using System.Text.RegularExpressions;

namespace MRTW.Core;

public sealed class PrivacyRedactor
{
    private static readonly Regex UserPath = new(@"C:\\Users\\([^\\]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PrivateIp = new(@"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", RegexOptions.Compiled);
    private static readonly Regex UncPath = new(@"\\\\[^\\/\s]+\\[^\s\""']*", RegexOptions.Compiled);
    private static readonly Regex Url = new(@"https?://[^\s\""'<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public CaseData Redact(CaseData data)
    {
        return data with
        {
            SamplePath = RedactText(data.SamplePath),
            StaticAnalysis = data.StaticAnalysis is null ? null : Redact(data.StaticAnalysis),
            Processes = data.Processes.Select(p => p with
            {
                CommandLine = RedactText(p.CommandLine),
                ImagePath = RedactText(p.ImagePath)
            }).ToArray(),
            Events = data.Events.Select(e => e with
            {
                ObjectValue = RedactText(e.ObjectValue),
                Summary = RedactText(e.Summary),
                RawJson = RedactText(e.RawJson)
            }).ToArray(),
            Artifacts = data.Artifacts.Select(a => a with
            {
                Value = RedactText(a.Value),
                RelatedProcesses = RedactText(a.RelatedProcesses)
            }).ToArray(),
            NetworkSessions = data.NetworkSessions.Select(n => n with
            {
                ResolvedIp = RedactText(n.ResolvedIp),
                RemoteIp = RedactText(n.RemoteIp)
            }).ToArray(),
            AnalystNotes = RedactText(data.AnalystNotes)
            ,RawEvidenceFiles = Array.Empty<string>(),
            PreservedFiles = Array.Empty<PreservedFile>()
            ,RawEvidence = Array.Empty<RawEvidenceFile>()
        };
    }

    public string RedactText(string value)
    {
        string text = UserPath.Replace(value, @"C:\Users\<USER>");
        text = PrivateIp.Replace(text, "<PRIVATE_IP>");
        text = UncPath.Replace(text, "<UNC_PATH>");
        text = Url.Replace(text, "<URL>");
        text = text.Replace(Environment.UserName, "<USER>", StringComparison.OrdinalIgnoreCase);
        string host = Dns.GetHostName();
        if (!string.IsNullOrWhiteSpace(host))
        {
            text = text.Replace(host, "<HOST>", StringComparison.OrdinalIgnoreCase);
        }

        return text;
    }

    public StaticAnalysisResult Redact(StaticAnalysisResult result) => result with
    {
        FullPath = RedactText(result.FullPath),
        SuspiciousStrings = result.SuspiciousStrings.Select(RedactText).ToArray(),
        PdbPath = RedactText(result.PdbPath),
        NonPeTriage = result.NonPeTriage is null ? null : result.NonPeTriage with
        {
            Format = RedactText(result.NonPeTriage.Format),
            Indicators = result.NonPeTriage.Indicators.Select(RedactText).ToArray(),
            UrlCandidates = result.NonPeTriage.UrlCandidates.Select(RedactText).ToArray(),
            CommandCandidates = result.NonPeTriage.CommandCandidates.Select(RedactText).ToArray(),
            EncodedContentMarkers = result.NonPeTriage.EncodedContentMarkers.Select(RedactText).ToArray(),
            ContainerEntries = result.NonPeTriage.ContainerEntries.Select(RedactText).ToArray(),
            SafetyWarnings = result.NonPeTriage.SafetyWarnings.Select(RedactText).ToArray()
        }
    };
}
