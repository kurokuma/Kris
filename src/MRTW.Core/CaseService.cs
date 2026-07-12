using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace MRTW.Core;

public sealed class CaseService
{
    private const long MaxCaseBytes = 64L * 1024 * 1024;
    private static readonly JsonSerializerOptions InputJsonOptions = new(JsonDefaults.Options) { MaxDepth = 32 };
    public CaseData Load(string casePath)
    {
        if (File.Exists(casePath) && Path.GetFileName(casePath).Equals("case.sqlite", StringComparison.OrdinalIgnoreCase))
        {
            return LoadSqlite(casePath);
        }

        string caseJson = ResolveCaseJson(casePath);
        var info = new FileInfo(caseJson);
        if (info.Length > MaxCaseBytes) throw new InvalidDataException("Case JSON exceeds the 64 MiB input limit.");
        var loaded = JsonSerializer.Deserialize<CaseData>(File.ReadAllBytes(caseJson), InputJsonOptions)
            ?? throw new InvalidOperationException($"Could not load case JSON: {caseJson}");
        Validate(loaded);
        return loaded with { TrustedEvidenceRoot = Path.GetDirectoryName(Path.GetFullPath(caseJson))! };
    }

    public string ResolveCaseDirectory(string casePath)
    {
        if (Directory.Exists(casePath))
        {
            return Path.GetFullPath(casePath);
        }

        if (File.Exists(casePath))
        {
            return Path.GetDirectoryName(Path.GetFullPath(casePath)) ?? Environment.CurrentDirectory;
        }

        throw new FileNotFoundException("Case path was not found.", casePath);
    }

    public IReadOnlyList<CaseSummary> List(string workspace)
    {
        if (!Directory.Exists(workspace))
        {
            return Array.Empty<CaseSummary>();
        }

        var summaries = new List<CaseSummary>();
        foreach (string caseJson in Directory.EnumerateFiles(workspace, "case.json", SearchOption.AllDirectories))
        {
            try
            {
                if (new FileInfo(caseJson).Length > MaxCaseBytes) continue;
                var data = JsonSerializer.Deserialize<CaseData>(File.ReadAllBytes(caseJson), InputJsonOptions);
                if (data is not null)
                {
                    Validate(data);
                    summaries.Add(new CaseSummary(data.CaseName, data.SampleName, data.Sha256, "Completed", data.StartedAt, data.Duration, data.Events.Count, data.Processes.Count, Path.GetDirectoryName(caseJson) ?? workspace));
                }
            }
            catch
            {
                // A single corrupt case should not hide the rest of the workspace.
            }
        }

        return summaries.OrderByDescending(s => s.StartedAt).ToArray();
    }

    public void SaveNotes(string casePath, string notes)
    {
        string caseJson = ResolveCaseJson(casePath);
        var data = Load(casePath) with { AnalystNotes = notes };
        File.WriteAllText(caseJson, JsonSerializer.Serialize(data, JsonDefaults.Options));
    }

    private static string ResolveCaseJson(string casePath)
    {
        if (Directory.Exists(casePath))
        {
            string candidate = Path.Combine(casePath, "case.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        if (File.Exists(casePath))
        {
            if (Path.GetFileName(casePath).Equals("case.json", StringComparison.OrdinalIgnoreCase))
            {
                return casePath;
            }

            string candidate = Path.Combine(Path.GetDirectoryName(casePath) ?? ".", "case.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("case.json was not found for the requested case.", casePath);
    }

    private static CaseData LoadSqlite(string sqlitePath)
    {
        if (new FileInfo(sqlitePath).Length > 512L * 1024 * 1024) throw new InvalidDataException("Case SQLite exceeds the 512 MiB input limit.");
        using var connection = new SqliteConnection($"Data Source={sqlitePath};Mode=ReadOnly;Pooling=False");
        connection.Open();

        using var caseCommand = connection.CreateCommand();
        caseCommand.CommandText = "SELECT case_id, case_name, sample_name, sample_path, sha256, started_at, duration_seconds, analyst_notes FROM cases LIMIT 1";
        using var caseReader = caseCommand.ExecuteReader();
        if (!caseReader.Read())
        {
            throw new InvalidOperationException($"SQLite case has no cases row: {sqlitePath}");
        }

        string caseId = Text(caseReader, 0); string caseName = Text(caseReader, 1); string sampleName = Text(caseReader, 2); string samplePath = Text(caseReader, 3); string sha256 = Text(caseReader, 4);
        var startedAt = DateTimeOffset.TryParse(Text(caseReader, 5), out var parsedStarted) ? parsedStarted : DateTimeOffset.Now;
        var duration = TimeSpan.FromSeconds(caseReader.GetDouble(6));
        string analystNotes = Text(caseReader, 7, 1024 * 1024);
        caseReader.Close();

        var processes = ReadProcesses(connection).ToArray();
        var events = ReadEvents(connection, caseId, startedAt, processes).ToArray();
        var artifacts = ReadArtifacts(connection).ToArray();
        var network = ReadNetworkSessions(connection).ToArray();
        var staticAnalysis = ReadStaticAnalysis(connection);
        var quality = ReadQuality(connection);
        var rawEvidenceMetadata = ReadJsonTable<RawEvidenceFile[]>(connection, "raw_evidence") ?? [];
        var preservedFiles = ReadJsonTable<PreservedFile[]>(connection, "preserved_files") ?? [];

        var result = new CaseData(
            caseId,
            caseName,
            sampleName,
            samplePath,
            sha256,
            startedAt,
            duration,
            staticAnalysis,
            processes,
            events,
            artifacts,
            network,
            analystNotes,
            quality,
            rawEvidenceMetadata.Select(r => r.StoredPath).ToArray(),
            preservedFiles) { TrustedEvidenceRoot = Path.GetDirectoryName(Path.GetFullPath(sqlitePath))!, RawEvidence = rawEvidenceMetadata };
        Validate(result);
        return result;
    }

    private static void Validate(CaseData data)
    {
        if (data.Events.Count > 1_000_000 || data.Processes.Count > 100_000 || data.Artifacts.Count > 250_000 || data.NetworkSessions.Count > 250_000 ||
            (data.RawEvidenceFiles?.Count ?? 0) > 32 || (data.PreservedFiles?.Count ?? 0) > 128)
            throw new InvalidDataException("Case collection count limit exceeded.");
    }

    private static T? ReadJsonTable<T>(SqliteConnection connection, string table)
    {
        if (!HasTable(connection, table)) return default;
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT json FROM {table} LIMIT 1";
        try { return command.ExecuteScalar() is string json && json.Length <= 4 * 1024 * 1024 ? JsonSerializer.Deserialize<T>(json, InputJsonOptions) : default; }
        catch { return default; }
    }

    private static CaseQuality? ReadQuality(SqliteConnection connection)
    {
        if (!HasTable(connection, "case_quality"))
        {
            return null;
        }
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT json FROM case_quality LIMIT 1";
        object? value = command.ExecuteScalar();
        try
        {
            return value is string json && json.Length <= 1024 * 1024 ? JsonSerializer.Deserialize<CaseQuality>(json, InputJsonOptions) : null;
        }
        catch
        {
            return null;
        }
    }

    private static StaticAnalysisResult? ReadStaticAnalysis(SqliteConnection connection)
    {
        if (!HasTable(connection, "static_analysis"))
        {
            return null;
        }

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT json FROM static_analysis LIMIT 1";
        object? value = command.ExecuteScalar();
        if (value is not string json || string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return json.Length <= 16 * 1024 * 1024 ? JsonSerializer.Deserialize<StaticAnalysisResult>(json, InputJsonOptions) : null;
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<ProcessNode> ReadProcesses(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT pid, parent_pid, name, process_guid, command_line, image_path, start_time, end_time, event_count, network_count, file_count, registry_count FROM processes ORDER BY start_time LIMIT 100001";
        using var reader = command.ExecuteReader();
        int count = 0;
        while (reader.Read())
        {
            if (++count > 100000) throw new InvalidDataException("Process row limit exceeded.");
            yield return new ProcessNode(
                Text(reader, 2),
                reader.GetInt32(0),
                reader.IsDBNull(1) ? null : reader.GetInt32(1),
                Text(reader, 3), Text(reader, 4), Text(reader, 5),
                ParseDate(reader, 6),
                reader.IsDBNull(7) ? null : ParseDate(reader, 7),
                reader.GetInt32(8),
                reader.GetInt32(9),
                reader.GetInt32(10),
                reader.GetInt32(11));
        }
    }

    private static IEnumerable<TimelineEvent> ReadEvents(SqliteConnection connection, string caseId, DateTimeOffset startedAt, IReadOnlyList<ProcessNode> processes)
    {
        bool hasProcessGuid = HasColumn(connection, "events", "process_guid");
        bool hasCapturedAtUtc = HasColumn(connection, "events", "captured_at_utc");
        using var command = connection.CreateCommand();
        command.CommandText = hasProcessGuid && hasCapturedAtUtc
            ? "SELECT id, time, process, pid, process_guid, category, action, object_value, summary, technique_id, technique_name, confidence, severity, source, raw_json, captured_at_utc FROM events ORDER BY id LIMIT 1000001"
            : hasProcessGuid
            ? "SELECT id, time, process, pid, process_guid, category, action, object_value, summary, technique_id, technique_name, confidence, severity, source, raw_json FROM events ORDER BY id LIMIT 1000001"
            : "SELECT id, time, process, pid, category, action, object_value, summary, technique_id, technique_name, confidence, severity, source, raw_json FROM events ORDER BY id LIMIT 1000001";
        using var reader = command.ExecuteReader();
        int count = 0;
        while (reader.Read())
        {
            if (++count > 1000000) throw new InvalidDataException("Event row limit exceeded.");
            int id = reader.GetInt32(0);
            var time = TimeSpan.TryParse(Text(reader, 1), out var parsedTime) ? parsedTime : TimeSpan.Zero;
            string process = Text(reader, 2);
            int pid = reader.GetInt32(3);
            int shift = hasProcessGuid ? 1 : 0;
            string processGuid = hasProcessGuid ? Text(reader, 4) : ResolveProcessGuid(caseId, startedAt, time, pid, process, processes);
            yield return new TimelineEvent(
                id,
                time,
                process,
                pid,
                ParseEnum(Text(reader, 4 + shift), EventCategory.Api),
                Text(reader, 5 + shift), Text(reader, 6 + shift), Text(reader, 7 + shift),
                ParseEnum(Text(reader, 11 + shift), EventSeverity.Low),
                Text(reader, 12 + shift), Text(reader, 13 + shift, 2 * 1024 * 1024),
                Text(reader, 8 + shift), Text(reader, 9 + shift), Text(reader, 10 + shift),
                processGuid,
                hasCapturedAtUtc && DateTimeOffset.TryParse(Text(reader, 15), out var captured) ? captured : startedAt.Add(time));
        }
    }

    private static IEnumerable<ArtifactItem> ReadArtifacts(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT type, value, first_seen, last_seen, event_count, related_processes, severity FROM artifacts LIMIT 250001";
        using var reader = command.ExecuteReader();
        int count = 0;
        while (reader.Read())
        {
            if (++count > 250000) throw new InvalidDataException("Artifact row limit exceeded.");
            yield return new ArtifactItem(
                Text(reader, 0), Text(reader, 1),
                ParseDate(reader, 2),
                ParseDate(reader, 3),
                reader.GetInt32(4),
                Text(reader, 5),
                ParseEnum(Text(reader, 6), EventSeverity.Low));
        }
    }

    private static IEnumerable<NetworkSession> ReadNetworkSessions(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        bool v3 = HasColumn(connection, "network_sessions", "coverage");
        bool http = HasColumn(connection, "network_sessions", "http_method");
        command.CommandText = "SELECT process, domain, resolved_ip, remote_ip, port, protocol, first_seen, bytes_sent, bytes_received, user_agent, sni" + (v3 ? ", dns_status, dns_answers, coverage" : "") + (http ? ", http_method, http_host, http_uri, http_headers" : "") + " FROM network_sessions LIMIT 250001";
        using var reader = command.ExecuteReader();
        int count = 0;
        while (reader.Read())
        {
            if (++count > 250000) throw new InvalidDataException("Network row limit exceeded.");
            yield return new NetworkSession(
                Text(reader, 0), Text(reader, 1), Text(reader, 2), Text(reader, 3),
                reader.GetInt32(4),
                Text(reader, 5),
                TimeSpan.TryParse(Text(reader, 6), out var firstSeen) ? firstSeen : TimeSpan.Zero,
                reader.GetInt64(7),
                reader.GetInt64(8),
                Text(reader, 9), Text(reader, 10),
                v3 ? Text(reader, 11) : "", v3 ? Text(reader, 12) : "", v3 ? Text(reader, 13) : "metadata-only",
                http ? Text(reader, 14) : "", http ? Text(reader, 15) : "", http ? Text(reader, 16) : "", http ? Text(reader, 17, 256 * 1024) : "");
        }
    }

    private static string Text(SqliteDataReader reader, int index, int maxChars = 64 * 1024)
    {
        if (reader.IsDBNull(index)) return "";
        // Microsoft.Data.Sqlite 9 can access-violate on GetChars(..., null, ...).
        // SQLite file size and row limits bound allocation; enforce the logical cell cap immediately after materialization.
        string value = reader.GetString(index);
        if (value.Length > maxChars) throw new InvalidDataException("SQLite text cell limit exceeded.");
        return value;
    }

    private static bool HasColumn(SqliteConnection connection, string table, string column)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({table})";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (Text(reader, 1, 256).Equals(column, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasTable(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name LIMIT 1";
        command.Parameters.AddWithValue("$name", table);
        return command.ExecuteScalar() is not null;
    }

    private static DateTimeOffset ParseDate(SqliteDataReader reader, int ordinal) =>
        DateTimeOffset.TryParse(Text(reader, ordinal), out var parsed) ? parsed : DateTimeOffset.MinValue;

    private static T ParseEnum<T>(string value, T fallback) where T : struct =>
        Enum.TryParse<T>(value, true, out var parsed) ? parsed : fallback;

    private static string ResolveProcessGuid(string caseId, DateTimeOffset startedAt, TimeSpan eventTime, int pid, string processName, IReadOnlyList<ProcessNode> processes)
    {
        var process = processes.FirstOrDefault(p => p.Pid == pid && p.Name.Equals(processName, StringComparison.OrdinalIgnoreCase));
        if (process is not null && !string.IsNullOrWhiteSpace(process.ProcessGuid))
        {
            return process.ProcessGuid;
        }

        var samePid = processes.Where(p => p.Pid == pid).ToArray();
        if (pid > 0 && samePid.Length == 1 && !string.IsNullOrWhiteSpace(samePid[0].ProcessGuid))
        {
            return samePid[0].ProcessGuid;
        }

        return $"{caseId}:{pid}:{startedAt.Add(eventTime).UtcTicks}";
    }
}

public sealed record CaseSummary(
    string CaseName,
    string SampleName,
    string Sha256,
    string Status,
    DateTimeOffset StartedAt,
    TimeSpan Duration,
    int EventCount,
    int ProcessCount,
    string Path);
