using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace MRTW.Core;

public sealed class CaseService
{
    public CaseData Load(string casePath)
    {
        if (File.Exists(casePath) && Path.GetFileName(casePath).Equals("case.sqlite", StringComparison.OrdinalIgnoreCase))
        {
            return LoadSqlite(casePath);
        }

        string caseJson = ResolveCaseJson(casePath);
        return JsonSerializer.Deserialize<CaseData>(File.ReadAllText(caseJson), JsonDefaults.Options)
            ?? throw new InvalidOperationException($"Could not load case JSON: {caseJson}");
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
                var data = JsonSerializer.Deserialize<CaseData>(File.ReadAllText(caseJson), JsonDefaults.Options);
                if (data is not null)
                {
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
        using var connection = new SqliteConnection($"Data Source={sqlitePath};Mode=ReadOnly;Pooling=False");
        connection.Open();

        using var caseCommand = connection.CreateCommand();
        caseCommand.CommandText = "SELECT case_id, case_name, sample_name, sample_path, sha256, started_at, duration_seconds, analyst_notes FROM cases LIMIT 1";
        using var caseReader = caseCommand.ExecuteReader();
        if (!caseReader.Read())
        {
            throw new InvalidOperationException($"SQLite case has no cases row: {sqlitePath}");
        }

        string caseId = caseReader.GetString(0);
        string caseName = caseReader.GetString(1);
        string sampleName = caseReader.GetString(2);
        string samplePath = caseReader.GetString(3);
        string sha256 = caseReader.GetString(4);
        var startedAt = DateTimeOffset.TryParse(caseReader.GetString(5), out var parsedStarted) ? parsedStarted : DateTimeOffset.Now;
        var duration = TimeSpan.FromSeconds(caseReader.GetDouble(6));
        string analystNotes = caseReader.GetString(7);
        caseReader.Close();

        var processes = ReadProcesses(connection).ToArray();
        var events = ReadEvents(connection, caseId, startedAt, processes).ToArray();
        var artifacts = ReadArtifacts(connection).ToArray();
        var network = ReadNetworkSessions(connection).ToArray();
        var staticAnalysis = ReadStaticAnalysis(connection);
        var quality = ReadQuality(connection);

        return new CaseData(
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
            quality);
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
            return value is string json ? JsonSerializer.Deserialize<CaseQuality>(json, JsonDefaults.Options) : null;
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
            return JsonSerializer.Deserialize<StaticAnalysisResult>(json, JsonDefaults.Options);
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<ProcessNode> ReadProcesses(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT pid, parent_pid, name, process_guid, command_line, image_path, start_time, end_time, event_count, network_count, file_count, registry_count FROM processes ORDER BY start_time";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return new ProcessNode(
                reader.GetString(2),
                reader.GetInt32(0),
                reader.IsDBNull(1) ? null : reader.GetInt32(1),
                reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                reader.IsDBNull(5) ? string.Empty : reader.GetString(5),
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
            ? "SELECT id, time, process, pid, process_guid, category, action, object_value, summary, technique_id, technique_name, confidence, severity, source, raw_json, captured_at_utc FROM events ORDER BY id"
            : hasProcessGuid
            ? "SELECT id, time, process, pid, process_guid, category, action, object_value, summary, technique_id, technique_name, confidence, severity, source, raw_json FROM events ORDER BY id"
            : "SELECT id, time, process, pid, category, action, object_value, summary, technique_id, technique_name, confidence, severity, source, raw_json FROM events ORDER BY id";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            int id = reader.GetInt32(0);
            var time = TimeSpan.TryParse(reader.GetString(1), out var parsedTime) ? parsedTime : TimeSpan.Zero;
            string process = reader.GetString(2);
            int pid = reader.GetInt32(3);
            int shift = hasProcessGuid ? 1 : 0;
            string processGuid = hasProcessGuid && !reader.IsDBNull(4) ? reader.GetString(4) : ResolveProcessGuid(caseId, startedAt, time, pid, process, processes);
            yield return new TimelineEvent(
                id,
                time,
                process,
                pid,
                ParseEnum(reader.GetString(4 + shift), EventCategory.Api),
                reader.GetString(5 + shift),
                reader.GetString(6 + shift),
                reader.GetString(7 + shift),
                ParseEnum(reader.GetString(11 + shift), EventSeverity.Low),
                reader.GetString(12 + shift),
                reader.GetString(13 + shift),
                reader.IsDBNull(8 + shift) ? string.Empty : reader.GetString(8 + shift),
                reader.IsDBNull(9 + shift) ? string.Empty : reader.GetString(9 + shift),
                reader.IsDBNull(10 + shift) ? string.Empty : reader.GetString(10 + shift),
                processGuid,
                hasCapturedAtUtc && !reader.IsDBNull(15) && DateTimeOffset.TryParse(reader.GetString(15), out var captured) ? captured : startedAt.Add(time));
        }
    }

    private static IEnumerable<ArtifactItem> ReadArtifacts(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT type, value, first_seen, last_seen, event_count, related_processes, severity FROM artifacts";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return new ArtifactItem(
                reader.GetString(0),
                reader.GetString(1),
                ParseDate(reader, 2),
                ParseDate(reader, 3),
                reader.GetInt32(4),
                reader.GetString(5),
                ParseEnum(reader.GetString(6), EventSeverity.Low));
        }
    }

    private static IEnumerable<NetworkSession> ReadNetworkSessions(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT process, domain, resolved_ip, remote_ip, port, protocol, first_seen, bytes_sent, bytes_received, user_agent, sni FROM network_sessions";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return new NetworkSession(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetInt32(4),
                reader.GetString(5),
                TimeSpan.TryParse(reader.GetString(6), out var firstSeen) ? firstSeen : TimeSpan.Zero,
                reader.GetInt64(7),
                reader.GetInt64(8),
                reader.GetString(9),
                reader.GetString(10));
        }
    }

    private static bool HasColumn(SqliteConnection connection, string table, string column)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({table})";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (reader.GetString(1).Equals(column, StringComparison.OrdinalIgnoreCase))
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
        DateTimeOffset.TryParse(reader.GetString(ordinal), out var parsed) ? parsed : DateTimeOffset.MinValue;

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
