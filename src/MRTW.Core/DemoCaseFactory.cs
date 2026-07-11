using System.Text.Json;

namespace MRTW.Core;

public static class DemoCaseFactory
{
    public static CaseData Create(string samplePath, StaticAnalysisResult? staticAnalysis = null, int durationSeconds = 60)
    {
        string sampleName = string.IsNullOrWhiteSpace(samplePath) ? "sample.exe" : Path.GetFileName(samplePath);
        string sha = staticAnalysis?.Sha256 ?? "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd001122334455667788";
        var started = DateTimeOffset.Now;
        string caseId = "case-" + Guid.NewGuid().ToString("N");
        var processes = new[]
        {
            new ProcessNode(sampleName, 3260, null, StableProcessGuid(caseId, 3260, started), Quote(samplePath), samplePath, started, null, 23, 3, 4, 2),
            new ProcessNode("powershell.exe", 4124, 3260, StableProcessGuid(caseId, 4124, started.AddMilliseconds(612)), "powershell -window hidden -nop -enc ...", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", started.AddMilliseconds(612), null, 11, 2, 6, 3),
            new ProcessNode("updater.exe", 5240, 4124, StableProcessGuid(caseId, 5240, started.AddSeconds(3.789)), @"C:\Users\user\AppData\Roaming\updater.exe", @"C:\Users\user\AppData\Roaming\updater.exe", started.AddSeconds(3.789), null, 21, 5, 8, 4),
            new ProcessNode("rundll32.exe", 6312, 5240, StableProcessGuid(caseId, 6312, started.AddSeconds(4.92)), @"rundll32.exe C:\Samples\update.dll,DllRegisterServer", @"C:\Windows\System32\rundll32.exe", started.AddSeconds(4.92), null, 4, 1, 1, 0)
        };

        var events = new List<TimelineEvent>
        {
            E(1, 0, sampleName, 3260, EventCategory.Process, "Process Start", sampleName, "Process started", EventSeverity.Informational, "ETW", processes[0].ProcessGuid),
            E(2, 153, sampleName, 3260, EventCategory.File, "File Write", @"C:\Users\user\AppData\Roaming\updater.exe", "Wrote 532 KB", EventSeverity.High, "Hook", processes[0].ProcessGuid),
            E(3, 395, sampleName, 3260, EventCategory.Registry, "Reg Set Value", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "Set persistence Run key", EventSeverity.High, "Hook", processes[0].ProcessGuid),
            E(4, 612, sampleName, 3260, EventCategory.Process, "Process Start", "powershell.exe", "Launched PowerShell", EventSeverity.Medium, "ETW", processes[0].ProcessGuid),
            E(5, 1021, "powershell.exe", 4124, EventCategory.Api, "CryptUnprotectData", "Crypt32.dll", "Decrypted data", EventSeverity.High, "Hook", processes[1].ProcessGuid),
            E(6, 1342, "powershell.exe", 4124, EventCategory.Dns, "DNS Query", "example.com", "A query for example.com", EventSeverity.Medium, "ETW", processes[1].ProcessGuid),
            E(7, 1358, "powershell.exe", 4124, EventCategory.Network, "TCP Connect", "185.10.10.5:443", "TCP connection established", EventSeverity.High, "ETW", processes[1].ProcessGuid),
            E(8, 1892, "powershell.exe", 4124, EventCategory.File, "File Write", @"C:\Users\user\AppData\Roaming\config.dat", "Wrote 1.2 KB", EventSeverity.Medium, "Hook", processes[1].ProcessGuid),
            E(9, 2311, "powershell.exe", 4124, EventCategory.Registry, "Reg Set Value", @"HKCU\Software\Updater\Config\Id", "Set REG_SZ", EventSeverity.Medium, "Hook", processes[1].ProcessGuid),
            E(10, 2944, "powershell.exe", 4124, EventCategory.Api, "Load Library", "wininet.dll", "Loaded library", EventSeverity.Low, "Hook", processes[1].ProcessGuid),
            E(11, 3210, "powershell.exe", 4124, EventCategory.Network, "HTTP POST", "185.10.10.5/api/update", "POST /api/update", EventSeverity.High, "Hook", processes[1].ProcessGuid),
            E(12, 3789, "powershell.exe", 4124, EventCategory.Process, "Process Start", "updater.exe", "Started updater", EventSeverity.Medium, "ETW", processes[1].ProcessGuid),
            E(13, 3823, "updater.exe", 5240, EventCategory.File, "File Write", @"C:\Users\user\AppData\Roaming\data.bin", "Wrote 4.0 KB", EventSeverity.Medium, "Hook", processes[2].ProcessGuid),
            E(14, 4102, "updater.exe", 5240, EventCategory.Network, "TCP Connect", "185.10.10.5:443", "TCP connection established", EventSeverity.High, "ETW", processes[2].ProcessGuid),
            E(15, 4532, "updater.exe", 5240, EventCategory.Registry, "Reg Set Value", @"HKCU\Software\Updater\LastRun", "Set REG_QWORD", EventSeverity.Low, "Hook", processes[2].ProcessGuid),
            E(16, 5001, "updater.exe", 5240, EventCategory.Api, "CryptUnprotectData", "Crypt32.dll", "Decrypted credential blob", EventSeverity.High, "Hook", processes[2].ProcessGuid)
        };

        var artifacts = new[]
        {
            new ArtifactItem("Network Connections", "185.10.10.5:443, 104.16.132.229:80, 8.8.8.8:53", started, started.AddSeconds(4), 8, "powershell.exe, updater.exe", EventSeverity.High),
            new ArtifactItem("DNS Queries", "example.com, api.example.com, cdn.example.com", started.AddSeconds(1), started.AddSeconds(2), 5, "powershell.exe", EventSeverity.Medium),
            new ArtifactItem("Files Written", @"...\updater.exe, ...\config.dat, ...\data.bin, ...\log.txt", started, started.AddSeconds(4), 12, sampleName + ", updater.exe", EventSeverity.High),
            new ArtifactItem("Registry Changes", @"HKCU\...\Run\Updater, HKCU\Software\Updater\Config\Id", started, started.AddSeconds(4), 9, sampleName + ", powershell.exe", EventSeverity.High),
            new ArtifactItem("API Calls", "CryptUnprotectData, LoadLibrary, InternetOpenA, HttpOpenRequestA", started.AddSeconds(1), started.AddSeconds(5), 36, "powershell.exe, updater.exe", EventSeverity.High)
        };

        var network = new[]
        {
            new NetworkSession("updater.exe", "example.com", "185.10.10.5", "185.10.10.5", 443, "HTTPS", TimeSpan.FromMilliseconds(1102), 2600, 5290, "Mozilla/5.0 (Windows NT 10.0)", "example.com"),
            new NetworkSession("updater.exe", "ocsp.digicert.com", "23.56.67.89", "23.56.67.89", 443, "HTTPS", TimeSpan.FromMilliseconds(1356), 1210, 1840, "Microsoft-CryptoAPI/10.0", "ocsp.digicert.com"),
            new NetworkSession("updater.exe", "api.ipify.org", "104.26.10.27", "104.26.10.27", 443, "HTTPS", TimeSpan.FromMilliseconds(2012), 453, 305, "curl/7.78.0", "api.ipify.org"),
            new NetworkSession("updater.exe", "-", "-", "91.189.88.152", 80, "HTTP", TimeSpan.FromMilliseconds(2731), 1120, 1340, "Mozilla/5.0", "-")
        };

        return new CaseData(
            caseId,
            $"{Path.GetFileNameWithoutExtension(sampleName)}_{sha[..Math.Min(8, sha.Length)]}_{DateTime.Now:yyyyMMdd_HHmmss}",
            sampleName,
            samplePath,
            sha,
            started,
            TimeSpan.FromSeconds(durationSeconds),
            staticAnalysis,
            processes,
            events,
            artifacts,
            network,
            "The sample drops a file to the AppData Roaming directory and establishes outbound connections over TLS. Persistence is represented by a Run key.");
    }

    private static TimelineEvent E(int id, int ms, string process, int pid, EventCategory category, string action, string obj, string summary, EventSeverity severity, string source, string processGuid)
    {
        var raw = JsonSerializer.Serialize(new
        {
            id,
            timestamp = DateTimeOffset.Now.AddMilliseconds(ms),
            process = new { pid, name = process },
            category = category.ToString(),
            action,
            obj,
            severity = severity.ToString()
        }, JsonDefaults.Options);

        return new TimelineEvent(id, TimeSpan.FromMilliseconds(ms), process, pid, category, action, obj, summary, severity, source, raw, ProcessGuid: processGuid);
    }

    private static string StableProcessGuid(string caseId, int pid, DateTimeOffset start) =>
        $"{caseId}:{pid}:{start.UtcTicks}";

    private static string Quote(string value) => string.IsNullOrWhiteSpace(value) ? "\"C:\\Samples\\sample.exe\"" : $"\"{value}\"";
}
