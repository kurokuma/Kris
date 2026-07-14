using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace MRTW.Core;

public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };
}

public sealed class CaseExportService
{
    public void WriteCaseBundle(CaseData data, string caseDirectory, string formats)
    {
        WriteCaseBundle(data, caseDirectory, new ExportOptions(formats));
    }

    public void WriteCaseBundle(CaseData data, string caseDirectory, ExportOptions options)
    {
        var transientEvidence = (data.RawEvidenceFiles ?? []).Concat(data.PreservedFiles?.Select(p => p.StoredPath) ?? []).Where(Path.IsPathFullyQualified).ToArray();
        Directory.CreateDirectory(caseDirectory);
        var warnings = new List<string>();
        var requested = ParseFormats(options.Formats);
        if (options.PrivacyMode)
        {
            data = new PrivacyRedactor().Redact(data);
        }

        File.WriteAllText(Path.Combine(caseDirectory, "tool_version.txt"), "MRTW 1.0.0-preview" + Environment.NewLine, Encoding.UTF8);

        if (options.IncludeRaw && !options.PrivacyMode && data.RawEvidence is { Count: > 0 })
        {
            string rawDirectory = Path.Combine(caseDirectory, "raw_evidence");
            Directory.CreateDirectory(rawDirectory);
            var relative = new List<string>();
            var rawMetadata = new List<RawEvidenceFile>();
            foreach (var item in data.RawEvidence.Take(32))
            {
                string candidate = Path.IsPathFullyQualified(item.StoredPath) ? item.StoredPath : Path.Combine(data.TrustedEvidenceRoot, item.StoredPath);
                string destination = Path.Combine(rawDirectory, Path.GetFileName(candidate));
                if (!EvidencePathPolicy.CopyValidated(candidate, destination, data.CaseId, data.TrustedEvidenceRoot, "raw_evidence", 512L * 1024 * 1024, item.Sha256, out long size, out string hash)) continue;
                relative.Add(Path.GetRelativePath(caseDirectory, destination));
                rawMetadata.Add(item with { StoredPath = Path.GetRelativePath(caseDirectory, destination), Size = size, Sha256 = hash });
            }
            data = data with { RawEvidenceFiles = relative, RawEvidence = rawMetadata };
        }

        if (!options.PrivacyMode && data.PreservedFiles is { Count: > 0 })
        {
            string filesDirectory = Path.Combine(caseDirectory, "evidence", "files");
            Directory.CreateDirectory(filesDirectory);
            var exported = new List<object>();
            var portable = new List<PreservedFile>();
            foreach (var item in data.PreservedFiles.Take(128))
            {
                string candidate = Path.IsPathFullyQualified(item.StoredPath) ? item.StoredPath : Path.Combine(data.TrustedEvidenceRoot, item.StoredPath);
                string name = Path.GetFileName(candidate);
                string destination = Path.Combine(filesDirectory, name);
                if (!EvidencePathPolicy.CopyValidated(candidate, destination, data.CaseId, data.TrustedEvidenceRoot, Path.Combine("evidence", "files"), 32L * 1024 * 1024, item.Sha256, out long copied, out string hash)) continue;
                exported.Add(new { item.OriginalPath, stored_name = name, item.Size, item.Sha256, item.Reason });
                portable.Add(item with { StoredPath = Path.GetRelativePath(caseDirectory, destination), Size = copied, Sha256 = hash });
                if (options.IncludeSample && item.OriginalPath.Equals(data.SamplePath, StringComparison.OrdinalIgnoreCase) && item.Sha256.Equals(data.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    string sampleDir = Path.Combine(caseDirectory, "sample"); Directory.CreateDirectory(sampleDir);
                    File.Copy(destination, Path.Combine(sampleDir, Path.GetFileName(item.OriginalPath)), true);
                }
            }
            File.WriteAllText(Path.Combine(caseDirectory, "evidence", "files.json"), JsonSerializer.Serialize(exported, JsonDefaults.Options), Encoding.UTF8);
            data = data with { PreservedFiles = portable };
        }

        if (requested.Contains("json") || requested.Contains("all"))
        {
            File.WriteAllText(Path.Combine(caseDirectory, "case.json"), JsonSerializer.Serialize(data, JsonDefaults.Options), Encoding.UTF8);
            if (data.StaticAnalysis is not null)
            {
                File.WriteAllText(Path.Combine(caseDirectory, "sample_metadata.json"), JsonSerializer.Serialize(data.StaticAnalysis, JsonDefaults.Options), Encoding.UTF8);
            }
        }

        if (options.IncludeRaw && (requested.Contains("jsonl") || requested.Contains("all")))
        {
            File.WriteAllLines(Path.Combine(caseDirectory, "events.jsonl"), data.Events.Select(e => JsonSerializer.Serialize(e, JsonDefaults.Options)), Encoding.UTF8);
            File.WriteAllLines(Path.Combine(caseDirectory, "raw_events.jsonl"), data.Events.Select(e => e.RawJson), Encoding.UTF8);
        }

        if (requested.Contains("csv") || requested.Contains("all"))
        {
            File.WriteAllText(Path.Combine(caseDirectory, "timeline.csv"), ToCsv(data.Events), Encoding.UTF8);
            File.WriteAllText(Path.Combine(caseDirectory, "artifacts.csv"), ToCsv(data.Artifacts), Encoding.UTF8);
            File.WriteAllText(Path.Combine(caseDirectory, "processes.csv"), ToCsv(data.Processes), Encoding.UTF8);
            File.WriteAllText(Path.Combine(caseDirectory, "network.csv"), ToCsv(data.NetworkSessions), Encoding.UTF8);
            File.WriteAllText(Path.Combine(caseDirectory, "normalized_commands.csv"), ToCsv(data.NormalizedCommands), Encoding.UTF8);
        }

        if (requested.Contains("html") || requested.Contains("all"))
        {
            File.WriteAllText(Path.Combine(caseDirectory, "report.html"), BuildHtml(data), Encoding.UTF8);
        }

        if (requested.Contains("sqlite") || requested.Contains("all"))
        {
            WriteSqliteBundle(data, Path.Combine(caseDirectory, "case.sqlite"));
        }

        if (warnings.Count > 0)
        {
            File.WriteAllLines(Path.Combine(caseDirectory, "export_warnings.txt"), warnings, Encoding.UTF8);
        }

        WriteManifest(caseDirectory);

        if (options.Compress && (requested.Contains("zip") || requested.Contains("all")))
        {
            try
            {
                string zipPath = Path.Combine(caseDirectory, "case_export.zip");
                string tempZip = Path.Combine(Path.GetTempPath(), $"mrtw_{Guid.NewGuid():N}.zip");
                if (File.Exists(zipPath))
                {
                    File.Delete(zipPath);
                }
                ZipFile.CreateFromDirectory(caseDirectory, tempZip);
                File.Move(tempZip, zipPath);
            }
            catch (Exception ex)
            {
                warnings.Add($"ZIP compression failed: {ex.Message}");
            }
        }

        if (warnings.Count > 0)
        {
            File.WriteAllLines(Path.Combine(caseDirectory, "export_warnings.txt"), warnings, Encoding.UTF8);
        }

        WriteManifest(caseDirectory);
        foreach (string transient in transientEvidence)
        {
            if (EvidencePathPolicy.TryValidate(transient, data.CaseId, 512L * 1024 * 1024, null, out string trusted) &&
                trusted.StartsWith(EvidencePathPolicy.Root(data.CaseId), StringComparison.OrdinalIgnoreCase))
            {
                try { File.Delete(trusted); } catch { }
            }
        }
    }

    private static HashSet<string> ParseFormats(string formats) =>
        formats.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(f => f.ToLowerInvariant())
            .DefaultIfEmpty("html")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static string ToCsv(IEnumerable<TimelineEvent> events)
    {
        var sb = new StringBuilder("time,captured_at_utc,process,process_guid,category,action,object,summary,technique_id,technique_name,confidence,severity,source\r\n");
        foreach (var e in events)
        {
            sb.AppendLine(string.Join(',', Csv(e.Time.ToString(@"hh\:mm\:ss\.fff")), Csv(e.CapturedAtUtc?.ToString("O")), Csv(e.Process), Csv(e.ProcessGuid), e.Category, Csv(e.Action), Csv(e.ObjectValue), Csv(e.Summary), Csv(e.TechniqueId), Csv(e.TechniqueName), Csv(e.Confidence), e.Severity, e.Source));
        }
        return sb.ToString();
    }

    private static string ToCsv(IEnumerable<ArtifactItem> artifacts)
    {
        var sb = new StringBuilder("type,value,first_seen,last_seen,event_count,related_processes,severity\r\n");
        foreach (var a in artifacts)
        {
            sb.AppendLine(string.Join(',', Csv(a.Type), Csv(a.Value), a.FirstSeen, a.LastSeen, a.EventCount, Csv(a.RelatedProcesses), a.Severity));
        }
        return sb.ToString();
    }

    private static string ToCsv(IEnumerable<ProcessNode> processes)
    {
        var sb = new StringBuilder("process,pid,parent_pid,command_line,start_time,end_time,event_count,network_count,file_count,registry_count\r\n");
        foreach (var p in processes)
        {
            sb.AppendLine(string.Join(',', Csv(p.Name), p.Pid, p.ParentPid, Csv(p.CommandLine), p.StartTime, p.EndTime, p.EventCount, p.NetworkCount, p.FileCount, p.RegistryCount));
        }
        return sb.ToString();
    }

    private static string ToCsv(IEnumerable<NetworkSession> sessions)
    {
        var sb = new StringBuilder("process,domain,resolved_ip,remote_ip,port,protocol,first_seen,bytes_sent,bytes_received,user_agent,sni\r\n");
        foreach (var n in sessions)
        {
            sb.AppendLine(string.Join(',', Csv(n.Process), Csv(n.Domain), n.ResolvedIp, n.RemoteIp, n.Port, n.Protocol, n.FirstSeen, n.BytesSent, n.BytesReceived, Csv(n.UserAgent), Csv(n.Sni)));
        }
        return sb.ToString();
    }
    private static string ToCsv(IEnumerable<NormalizedCommand> commands)
    {
        var sb = new StringBuilder("original,normalized,decoder,status,failure_reason,lolbin,process_guid,pid,time,evidence_event_ids\r\n");
        foreach (var c in commands) sb.AppendLine(string.Join(',', Csv(c.Original), Csv(c.Normalized), Csv(c.Decoder), Csv(c.Status), Csv(c.FailureReason), Csv(c.LolBin), Csv(c.ProcessGuid), c.Pid, Csv(c.Time), Csv(string.Join(';', c.EvidenceEventIds ?? []))));
        return sb.ToString();
    }

    private static string Csv(object? value)
    {
        string text = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        // Spreadsheet applications evaluate leading formula markers even in quoted cells.
        if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@') text = "'" + text;
        return "\"" + text.Replace("\"", "\"\"") + "\"";
    }

    private static string BuildHtml(CaseData data)
    {
        string rows = string.Join(Environment.NewLine, data.Events.Select(e =>
            $"<tr><td>{e.Time:hh\\:mm\\:ss\\.fff}</td><td>{H(e.Process)}</td><td>{e.Category}</td><td>{H(e.Action)}</td><td>{H(e.ObjectValue)}</td><td>{H(e.Summary)}</td><td>{H(e.TechniqueId)}</td><td class='{e.Severity.ToString().ToLowerInvariant()}'>{e.Severity}</td></tr>"));
        string artifactRows = string.Join(Environment.NewLine, data.Artifacts.Select(a =>
            $"<tr><td>{H(a.Type)}</td><td>{H(a.Value)}</td><td>{a.EventCount}</td><td>{a.Severity}</td></tr>"));
        string qualityRows = string.Join(Environment.NewLine, (data.Quality?.Collectors ?? [])
            .Select(c => $"<tr><td>{H(c.Collector)}</td><td>{H(c.Status)}</td><td>{c.EventsReceived}</td><td>{c.EventsDropped}</td><td>{H(c.Message)}</td></tr>"));
        string triage = BuildNonPeTriageHtml(data.StaticAnalysis?.NonPeTriage);
        string commands = "<h2>Normalized Command Chains</h2><table><thead><tr><th>Status</th><th>LOLBin</th><th>Original</th><th>Normalized</th><th>Evidence</th></tr></thead><tbody>" + string.Join(string.Empty, data.NormalizedCommands.Select(c => $"<tr><td>{H(c.Status)}</td><td>{H(c.LolBin)}</td><td>{H(c.Original)}</td><td>{H(c.Normalized)}</td><td>{H(string.Join(',', c.EvidenceEventIds ?? []))}</td></tr>")) + "</tbody></table>";

        return $$"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MRTW Report - {{H(data.SampleName)}}</title>
<style>
body{margin:0;background:#08111c;color:#dbe7f5;font:14px Segoe UI,Arial,sans-serif}
header{padding:24px 32px;background:#0c1724;border-bottom:1px solid #223247}
h1{margin:0;font-size:28px}.meta{color:#93a4b8;margin-top:8px}
main{padding:24px 32px}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}
.card{border:1px solid #26384f;background:#101d2c;border-radius:8px;padding:16px}.num{font-size:28px;font-weight:700;color:#58a6ff}
table{width:100%;border-collapse:collapse;background:#0d1825;border:1px solid #26384f;margin-top:12px}
th,td{padding:9px 10px;border-bottom:1px solid #1f3044;text-align:left}th{background:#132134}
.high,.critical{color:#ff7b42}.medium{color:#ffc947}.low{color:#58a6ff}.informational{color:#9dc3e6}
</style>
</head>
<body>
<header><h1>MRTW Report</h1><div class="meta">{{H(data.SampleName)}} | SHA256 {{data.Sha256}} | {{data.StartedAt}}</div></header>
<main>
<section class="cards">
<div class="card"><div class="num">{{data.Processes.Count}}</div><div>Processes</div></div>
<div class="card"><div class="num">{{data.Events.Count(e => e.Category == EventCategory.Dns)}}</div><div>DNS Queries</div></div>
<div class="card"><div class="num">{{data.Events.Count(e => e.Category == EventCategory.Network)}}</div><div>Network Events</div></div>
<div class="card"><div class="num">{{data.Events.Count(e => e.Category == EventCategory.File)}}</div><div>File Events</div></div>
<div class="card"><div class="num">{{data.Events.Count(e => e.Category == EventCategory.Registry)}}</div><div>Registry Events</div></div>
</section>
<h2>Key Timeline Events</h2>
<table><thead><tr><th>Time</th><th>Process</th><th>Category</th><th>Action</th><th>Object</th><th>Summary</th><th>Technique</th><th>Severity</th></tr></thead><tbody>{{rows}}</tbody></table>
<h2>Artifacts</h2>
<table><thead><tr><th>Type</th><th>Value</th><th>Count</th><th>Severity</th></tr></thead><tbody>{{artifactRows}}</tbody></table>
<h2>Collection Quality</h2>
<p>Overall: {{H(data.Quality?.OverallStatus ?? "not recorded")}} | Network: {{H(data.Quality?.NetworkContainment ?? "not recorded")}}</p>
<table><thead><tr><th>Collector</th><th>Status</th><th>Events</th><th>Dropped</th><th>Message</th></tr></thead><tbody>{{qualityRows}}</tbody></table>
{{triage}}
{{commands}}
<h2>Analyst Notes</h2><p>{{H(data.AnalystNotes)}}</p>
</main>
</body>
</html>
""";
    }

    private static string BuildNonPeTriageHtml(NonPeTriageResult? triage)
    {
        if (triage is null) return string.Empty;
        string List(string title, IEnumerable<string> values) => $"<h3>{H(title)}</h3><ul>" + string.Join(string.Empty, values.Select(v => $"<li>{H(v)}</li>")) + "</ul>";
        return "<section><h2>Initial Access Triage</h2>" +
            $"<p><strong>Format:</strong> {H(triage.Format)} | <strong>Runtime start:</strong> {triage.CanExecute}</p>" +
            List("Indicators", triage.Indicators) + List("URL candidates", triage.UrlCandidates) +
            List("Command candidates", triage.CommandCandidates) + List("Encoded-content markers", triage.EncodedContentMarkers) +
            List("Container entries", triage.ContainerEntries) + List("Safety warnings", triage.SafetyWarnings) + "</section>";
    }

    private static void WriteSqliteBundle(CaseData data, string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var transaction = connection.BeginTransaction();

            ExecuteNonQuery(connection, transaction, """
CREATE TABLE cases(case_id TEXT PRIMARY KEY, case_name TEXT, sample_name TEXT, sample_path TEXT, sha256 TEXT, started_at TEXT, duration_seconds REAL, analyst_notes TEXT);
CREATE TABLE static_analysis(json TEXT);
CREATE TABLE processes(pid INTEGER, parent_pid INTEGER, name TEXT, process_guid TEXT, command_line TEXT, image_path TEXT, start_time TEXT, end_time TEXT, event_count INTEGER, network_count INTEGER, file_count INTEGER, registry_count INTEGER);
CREATE TABLE events(id INTEGER PRIMARY KEY, time TEXT, captured_at_utc TEXT, process TEXT, pid INTEGER, process_guid TEXT, category TEXT, action TEXT, object_value TEXT, summary TEXT, technique_id TEXT, technique_name TEXT, confidence TEXT, severity TEXT, source TEXT, raw_json TEXT);
CREATE TABLE artifacts(type TEXT, value TEXT, first_seen TEXT, last_seen TEXT, event_count INTEGER, related_processes TEXT, severity TEXT);
CREATE TABLE network_sessions(process TEXT, domain TEXT, resolved_ip TEXT, remote_ip TEXT, port INTEGER, protocol TEXT, first_seen TEXT, bytes_sent INTEGER, bytes_received INTEGER, user_agent TEXT, sni TEXT, dns_status TEXT, dns_answers TEXT, coverage TEXT, http_method TEXT, http_host TEXT, http_uri TEXT, http_headers TEXT);
CREATE TABLE case_quality(json TEXT);
CREATE TABLE raw_evidence(json TEXT);
CREATE TABLE preserved_files(json TEXT);
CREATE TABLE normalized_commands(json TEXT);
CREATE INDEX ix_events_time ON events(time);
CREATE INDEX ix_events_process ON events(process);
CREATE INDEX ix_events_category ON events(category);
""");

            Execute(connection, transaction,
                "INSERT INTO cases VALUES($case_id,$case_name,$sample_name,$sample_path,$sha256,$started_at,$duration_seconds,$analyst_notes)",
                ("$case_id", data.CaseId),
                ("$case_name", data.CaseName),
                ("$sample_name", data.SampleName),
                ("$sample_path", data.SamplePath),
                ("$sha256", data.Sha256),
                ("$started_at", data.StartedAt.ToString("O")),
                ("$duration_seconds", data.Duration.TotalSeconds),
                ("$analyst_notes", data.AnalystNotes));

            if (data.StaticAnalysis is not null)
            {
                Execute(connection, transaction,
                    "INSERT INTO static_analysis VALUES($json)",
                    ("$json", JsonSerializer.Serialize(data.StaticAnalysis, JsonDefaults.Options)));
            }
            if (data.Quality is not null)
            {
                Execute(connection, transaction, "INSERT INTO case_quality VALUES($json)",
                    ("$json", JsonSerializer.Serialize(data.Quality, JsonDefaults.Options)));
            }
            Execute(connection, transaction, "INSERT INTO raw_evidence VALUES($json)", ("$json", JsonSerializer.Serialize(data.RawEvidence, JsonDefaults.Options)));
            Execute(connection, transaction, "INSERT INTO preserved_files VALUES($json)", ("$json", JsonSerializer.Serialize(data.PreservedFiles ?? [], JsonDefaults.Options)));
            foreach (var item in data.NormalizedCommands) Execute(connection, transaction, "INSERT INTO normalized_commands VALUES($json)", ("$json", JsonSerializer.Serialize(item, JsonDefaults.Options)));

            foreach (var p in data.Processes)
            {
                Execute(connection, transaction,
                    "INSERT INTO processes VALUES($pid,$parent_pid,$name,$process_guid,$command_line,$image_path,$start_time,$end_time,$event_count,$network_count,$file_count,$registry_count)",
                    ("$pid", p.Pid),
                    ("$parent_pid", p.ParentPid),
                    ("$name", p.Name),
                    ("$process_guid", p.ProcessGuid),
                    ("$command_line", p.CommandLine),
                    ("$image_path", p.ImagePath),
                    ("$start_time", p.StartTime.ToString("O")),
                    ("$end_time", p.EndTime?.ToString("O")),
                    ("$event_count", p.EventCount),
                    ("$network_count", p.NetworkCount),
                    ("$file_count", p.FileCount),
                    ("$registry_count", p.RegistryCount));
            }

            foreach (var e in data.Events)
            {
                Execute(connection, transaction,
                    "INSERT INTO events VALUES($id,$time,$captured_at_utc,$process,$pid,$process_guid,$category,$action,$object_value,$summary,$technique_id,$technique_name,$confidence,$severity,$source,$raw_json)",
                    ("$id", e.Id),
                    ("$time", e.Time.ToString(@"hh\:mm\:ss\.fff")),
                    ("$captured_at_utc", e.CapturedAtUtc?.ToString("O")),
                    ("$process", e.Process),
                    ("$pid", e.Pid),
                    ("$process_guid", e.ProcessGuid),
                    ("$category", e.Category.ToString()),
                    ("$action", e.Action),
                    ("$object_value", e.ObjectValue),
                    ("$summary", e.Summary),
                    ("$technique_id", e.TechniqueId),
                    ("$technique_name", e.TechniqueName),
                    ("$confidence", e.Confidence),
                    ("$severity", e.Severity.ToString()),
                    ("$source", e.Source),
                    ("$raw_json", e.RawJson));
            }

            foreach (var a in data.Artifacts)
            {
                Execute(connection, transaction,
                    "INSERT INTO artifacts VALUES($type,$value,$first_seen,$last_seen,$event_count,$related_processes,$severity)",
                    ("$type", a.Type),
                    ("$value", a.Value),
                    ("$first_seen", a.FirstSeen.ToString("O")),
                    ("$last_seen", a.LastSeen.ToString("O")),
                    ("$event_count", a.EventCount),
                    ("$related_processes", a.RelatedProcesses),
                    ("$severity", a.Severity.ToString()));
            }

            foreach (var n in data.NetworkSessions)
            {
                Execute(connection, transaction,
                    "INSERT INTO network_sessions VALUES($process,$domain,$resolved_ip,$remote_ip,$port,$protocol,$first_seen,$bytes_sent,$bytes_received,$user_agent,$sni,$dns_status,$dns_answers,$coverage,$http_method,$http_host,$http_uri,$http_headers)",
                    ("$process", n.Process),
                    ("$domain", n.Domain),
                    ("$resolved_ip", n.ResolvedIp),
                    ("$remote_ip", n.RemoteIp),
                    ("$port", n.Port),
                    ("$protocol", n.Protocol),
                    ("$first_seen", n.FirstSeen.ToString(@"hh\:mm\:ss\.fff")),
                    ("$bytes_sent", n.BytesSent),
                    ("$bytes_received", n.BytesReceived),
                    ("$user_agent", n.UserAgent),
                    ("$sni", n.Sni),
                    ("$dns_status", n.DnsStatus),
                    ("$dns_answers", n.DnsAnswers),
                    ("$coverage", n.Coverage), ("$http_method", n.HttpMethod), ("$http_host", n.HttpHost), ("$http_uri", n.HttpUri), ("$http_headers", n.HttpHeaders));
            }

            transaction.Commit();
            connection.Close();
        }

        SqliteConnection.ClearAllPools();
    }

    private static void ExecuteNonQuery(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static void Execute(SqliteConnection connection, SqliteTransaction transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        command.ExecuteNonQuery();
    }

    private static void WriteManifest(string caseDirectory)
    {
        var files = Directory.EnumerateFiles(caseDirectory)
            .Where(path => Path.GetFileName(path) != "manifest.json")
            .Select(path => new
            {
                path = Path.GetFileName(path),
                sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant()
            })
            .OrderBy(f => f.path)
            .ToArray();

        var manifest = new
        {
            tool_version = "1.0.0-preview",
            schema_version = 3,
            created_at_utc = DateTimeOffset.UtcNow,
            files
        };
        File.WriteAllText(Path.Combine(caseDirectory, "manifest.json"), JsonSerializer.Serialize(manifest, JsonDefaults.Options), Encoding.UTF8);
    }

    private static string H(string value) => System.Net.WebUtility.HtmlEncode(value);
}
