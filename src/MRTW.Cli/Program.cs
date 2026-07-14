using MRTW.Core;
using MRTW.Collectors.Etw;

return await CliApp.RunAsync(args);

internal static class CliApp
{
    private static readonly System.Text.Json.JsonSerializerOptions CliJsonOptions = new(JsonDefaults.Options) { WriteIndented = false };
    public static Task<int> RunAsync(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "--help" or "-h")
            {
                Help();
                return Task.FromResult(0);
            }

            var command = args[0].ToLowerInvariant();
            var options = Parse(args.Skip(1).ToArray());
            bool jsonLog = Get(options, "log-format") == "json";

            return Task.FromResult(command switch
            {
                "version" => Version(jsonLog),
                "doctor" => Doctor(jsonLog),
                "static" => Static(options, jsonLog),
                "run" => Run(options, jsonLog),
                "export" => Export(options, jsonLog),
                "etw-smoke" => EtwSmoke(options, jsonLog),
                "batch" => Batch(options, jsonLog),
                "selftest" => SelfTest(options, jsonLog),
                "list" => ListCases(options),
                "open" => Open(options, jsonLog),
                _ => Error($"Unknown command: {command}", 1, jsonLog)
            });
        }
        catch (FileNotFoundException ex)
        {
            Console.Error.WriteLine($"ERROR: target not found: {ex.FileName}");
            return Task.FromResult(2);
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"ERROR: permission denied: {ex.Message}");
            return Task.FromResult(8);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return Task.FromResult(1);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return Task.FromResult(3);
        }
    }

    private static int Version(bool json)
    {
        Log(json, "version", new Dictionary<string, object?>
        {
            ["mrtw_cli"] = "1.0.0-preview",
            ["mrtw_core"] = "1.0.0-preview",
            ["schema"] = 1,
            ["hook_x64"] = new NativeHookLauncher().IsAvailable ? "available" : "not found",
            ["etw_collector"] = "TraceEvent"
        }, $"MRTW CLI: 1.0.0-preview\nMRTW Core: 1.0.0-preview\nSchema: 3\nHook x64: {(new NativeHookLauncher().IsAvailable ? "available" : "not found")}\nETW Collector: TraceEvent");
        return 0;
    }

    private static int Doctor(bool json)
    {
        var checks = new Dictionary<string, object?>
        {
            ["os"] = Environment.OSVersion.ToString(),
            ["process_architecture"] = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            ["dotnet"] = Environment.Version.ToString(),
            ["administrator"] = IsAdministrator(),
            ["workspace_writable"] = CanWrite(Environment.CurrentDirectory),
            ["sqlite_bundle"] = "Microsoft.Data.Sqlite",
            ["etw_access"] = IsAdministrator() ? "available" : "not elevated",
            ["traceevent"] = typeof(TraceEventEtwCollector).Assembly.GetName().Version?.ToString()
        };

        Log(json, "doctor", checks,
            $"MRTW Doctor\n[OK] OS: {Environment.OSVersion}\n[OK] .NET Runtime: {Environment.Version}\n[{(IsAdministrator() ? "OK" : "WARN")}] Administrator\n[OK] Workspace writable\n[OK] SQLite: Microsoft.Data.Sqlite\n[OK] TraceEvent: {typeof(TraceEventEtwCollector).Assembly.GetName().Version}\n[{(new NativeHookLauncher().IsAvailable ? "OK" : "WARN")}] Hook DLL: {(new NativeHookLauncher().IsAvailable ? "available" : "not found")}\n[INFO] Case schema: 3");
        return 0;
    }

    private static int Static(Dictionary<string, string?> options, bool json)
    {
        var config = new MrtwConfigService().Load(Get(options, "config"));
        string target = Required(options, "target");
        string output = Get(options, "out") ?? config.Exports;
        string formats = Get(options, "format") ?? "html,json";
        string? caseName = Get(options, "case-name");

        var result = new CaseRunner().Static(target, output, formats, caseName);
        Log(json, "static_completed", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["sha256"] = result.Sha256,
            ["file_type"] = result.FileType,
            ["architecture"] = result.Architecture,
            ["out"] = output
        }, $"[+] Static analysis completed: {Path.GetFileName(target)}\n[+] SHA256: {result.Sha256}\n[+] Output: {output}");
        return 0;
    }

    private static int Run(Dictionary<string, string?> options, bool json, bool logCompletion = true, Action<RunCompletion>? completed = null)
    {
        var config = new MrtwConfigService().Load(Get(options, "config"));
        var profileDefaults = ResolveProfile(config, Get(options, "profile"));
        string target = Get(options, "target") ?? string.Empty;
        string cmd = Get(options, "cmd") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(target) && string.IsNullOrWhiteSpace(cmd))
        {
            throw new ArgumentException("run requires --target <path> or --cmd <commandline>.");
        }

        if (!string.IsNullOrWhiteSpace(target) && !File.Exists(target))
        {
            throw new FileNotFoundException("Target file was not found.", target);
        }

        string effectiveTarget = string.IsNullOrWhiteSpace(target) ? "command.exe" : target;
        string type = Get(options, "type") ?? InferType(effectiveTarget, cmd);
        string runner = Get(options, "runner") ?? (type == "dll" ? "rundll32" : "none");
        string? exportFunc = Get(options, "export-func");
        if (type == "dll" && runner == "rundll32" && string.IsNullOrWhiteSpace(exportFunc))
        {
            exportFunc = "DllRegisterServer";
        }

        int duration = int.TryParse(Get(options, "duration"), out int d) ? d : profileDefaults.Duration;
        string output = Get(options, "out") ?? config.Workspace;
        string formats = Get(options, "format") ?? profileDefaults.Format;
        string timeoutAction = Get(options, "timeout-action") ?? profileDefaults.TimeoutAction;
        bool killTree = options.ContainsKey("kill-tree") || profileDefaults.KillTree || timeoutAction.Equals("kill", StringComparison.OrdinalIgnoreCase);
        bool executeTarget = !string.Equals(Get(options, "execute"), "off", StringComparison.OrdinalIgnoreCase);
        var exportOptions = new ExportOptions(
            formats,
            GetOnOff(options, "privacy-mode", false),
            GetOnOff(options, "include-sample", false),
            GetOnOff(options, "include-raw", true),
            GetOnOff(options, "compress", true));
        var profile = new ExecutionProfile(
            effectiveTarget,
            type,
            runner,
            exportFunc,
            string.IsNullOrWhiteSpace(cmd) ? BuildCommandLine(effectiveTarget, type, runner, exportFunc) : cmd,
            Get(options, "working-dir") ?? Path.GetDirectoryName(effectiveTarget) ?? Environment.CurrentDirectory,
            duration,
            GetOnOff(options, "etw", profileDefaults.Etw),
            GetOnOff(options, "hook", profileDefaults.Hook),
            GetOnOff(options, "snapshot-before", profileDefaults.SnapshotBefore),
            GetOnOff(options, "snapshot-after", profileDefaults.SnapshotAfter),
            Get(options, "network") ?? profileDefaults.Network,
            killTree,
            timeoutAction,
            executeTarget,
            exportOptions.PrivacyMode);

        var data = new AnalysisCaseRunner().Run(profile, output, exportOptions, Get(options, "case-name"), options.ContainsKey("overwrite"), options.ContainsKey("auto-suffix"));
        string casePath = Path.Combine(output, data.CaseName);
        completed?.Invoke(new RunCompletion(data.CaseId, casePath, data.Events.Count, data.Processes.Count));
        if (logCompletion)
        {
            Log(json, "analysis_completed", new Dictionary<string, object?>
            {
                ["case_id"] = data.CaseId,
                ["path"] = casePath,
                ["events"] = data.Events.Count,
                ["processes"] = data.Processes.Count
            }, $"[+] Case created: {casePath}\n[+] Static analysis completed\n[+] Runtime collector started\n[+] Snapshot diff completed\n[+] Analysis completed\n[+] Exported: report.html, case.json, events.jsonl, case.sqlite");
        }
        return 0;
    }

    private static int Export(Dictionary<string, string?> options, bool json)
    {
        var config = new MrtwConfigService().Load(Get(options, "config"));
        string casePath = Required(options, "case");
        string output = Get(options, "out") ?? config.Exports;
        string formats = Get(options, "format") ?? "html,csv,json";
        var data = new CaseService().Load(casePath);
        string exportDir = Path.Combine(output, data.CaseName);
        if (Directory.Exists(exportDir) && options.ContainsKey("overwrite"))
        {
            Directory.Delete(exportDir, true);
        }
        new CaseExportService().WriteCaseBundle(data, exportDir, new ExportOptions(
            formats,
            GetOnOff(options, "privacy-mode", false),
            GetOnOff(options, "include-sample", false),
            GetOnOff(options, "include-raw", true),
            GetOnOff(options, "compress", true)));
        Log(json, "export_completed", new Dictionary<string, object?> { ["out"] = exportDir, ["format"] = formats }, $"[+] Exported: {exportDir}");
        return 0;
    }

    private static int EtwSmoke(Dictionary<string, string?> options, bool json)
    {
        int duration = int.TryParse(Get(options, "duration"), out int seconds) ? seconds : 3;
        int? pid = int.TryParse(Get(options, "pid"), out int parsedPid) ? parsedPid : null;
        var result = new TraceEventEtwCollector().Collect(new EtwCollectorOptions(pid, TimeSpan.FromSeconds(duration)));
        if (!result.Started)
        {
            return Error($"ETW collector failed: {result.ErrorMessage}", 5, json);
        }

        Log(json, "etw_smoke_completed", new Dictionary<string, object?>
        {
            ["events"] = result.Events.Count,
            ["network_sessions"] = result.NetworkSessions.Count,
            ["duration_seconds"] = duration
        }, $"[+] ETW smoke completed\n[+] Events: {result.Events.Count}\n[+] Network sessions: {result.NetworkSessions.Count}");
        return 0;
    }

    private static int Batch(Dictionary<string, string?> options, bool json)
    {
        BatchAnalysisPolicy.RejectCommandOverride(options.ContainsKey("cmd"));
        string input = Required(options, "input");
        if (!Directory.Exists(input))
        {
            throw new DirectoryNotFoundException($"Batch input directory was not found: {input}");
        }

        var config = new MrtwConfigService().Load(Get(options, "config"));
        string output = Get(options, "out") ?? config.Workspace;
        int max = int.TryParse(Get(options, "max-samples"), out int m) ? m : int.MaxValue;
        if (max < 0)
        {
            throw new ArgumentException("--max-samples must be zero or greater.");
        }

        bool recursive = options.ContainsKey("recursive");
        bool privacyMode = GetOnOff(options, "privacy-mode", false);
        var files = Directory.EnumerateFiles(input, "*.*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Where(f => string.Equals(Path.GetExtension(f), ".exe", StringComparison.OrdinalIgnoreCase) || string.Equals(Path.GetExtension(f), ".dll", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .Take(max);
        var items = new List<BatchAnalysisItem>();
        foreach (string file in files)
        {
            var batchOptions = new Dictionary<string, string?>(options, StringComparer.OrdinalIgnoreCase)
            {
                ["target"] = file,
                ["out"] = output,
                ["case-name"] = null
            };
            RunCompletion? completion = null;
            try
            {
                int code = Run(batchOptions, json, logCompletion: false, completed: result => completion = result);
                BatchAnalysisItem item = code == 0
                    ? BatchItem(file, "succeeded", code, null, completion?.CaseOutput, privacyMode)
                    : BatchItem(file, "failed", code, $"Run returned exit code {code}.", completion?.CaseOutput, privacyMode);
                items.Add(item);
                if (json && code == 0 && completion is not null)
                {
                    Log(true, "analysis_completed", new Dictionary<string, object?>
                    {
                        ["case_id"] = completion.CaseId,
                        ["path"] = item.CaseOutput,
                        ["target"] = item.Target,
                        ["events"] = completion.Events,
                        ["processes"] = completion.Processes
                    }, string.Empty);
                }
                else if (json && code != 0)
                {
                    Log(true, "analysis_failed", new Dictionary<string, object?>
                    {
                        ["target"] = item.Target,
                        ["message"] = item.Reason,
                        ["code"] = item.ExitCode
                    }, string.Empty);
                }
            }
            catch (Exception ex)
            {
                // A containment failure is a failure for this target.  Do not alter its requested mode or retry in observe mode.
                BatchAnalysisItem item = BatchItem(file, "failed", BatchTargetExceptionCode(ex), ex.Message, completion?.CaseOutput, privacyMode);
                items.Add(item);
                if (json)
                {
                    Log(true, "analysis_failed", new Dictionary<string, object?>
                    {
                        ["target"] = item.Target,
                        ["message"] = item.Reason,
                        ["code"] = item.ExitCode
                    }, string.Empty);
                }
            }
        }

        var summary = new BatchAnalysisSummary(
            DateTimeOffset.UtcNow,
            items.Count(i => i.Status == "succeeded"),
            items.Count(i => i.Status == "failed"),
            items.Count(i => i.Status == "skipped"),
            items);
        string? summaryPath = Get(options, "summary");
        if (!string.IsNullOrWhiteSpace(summaryPath))
        {
            WriteSummaryAtomically(summaryPath, summary);
        }

        if (json)
        {
            Log(true, "batch_completed", BatchFields(summary), string.Empty);
        }
        else
        {
            Console.WriteLine($"[+] Batch completed: succeeded={summary.Succeeded}, failed={summary.Failed}, skipped={summary.Skipped}, exit_code={summary.ExitCode}");
            foreach (BatchAnalysisItem item in summary.Items)
            {
                Console.WriteLine($"[{item.Status.ToUpperInvariant()}] {item.Target} (exit={item.ExitCode}){(string.IsNullOrWhiteSpace(item.Reason) ? string.Empty : $": {item.Reason}")}{(string.IsNullOrWhiteSpace(item.CaseOutput) ? string.Empty : $" -> {item.CaseOutput}")}");
            }
            if (!string.IsNullOrWhiteSpace(summaryPath))
            {
                Console.WriteLine($"[+] Batch summary: {(privacyMode ? "<redacted>" : Path.GetFullPath(summaryPath))}");
            }
        }

        return summary.ExitCode;
    }

    private static BatchAnalysisItem BatchItem(string target, string status, int exitCode, string? reason, string? caseOutput, bool privacyMode)
    {
        if (!privacyMode)
        {
            return new BatchAnalysisItem(target, status, exitCode, reason, caseOutput);
        }

        return new BatchAnalysisItem(
            "<redacted>",
            status,
            exitCode,
            string.IsNullOrWhiteSpace(reason) ? null : "<redacted>",
            string.IsNullOrWhiteSpace(caseOutput) ? null : "<redacted>");
    }

    private static int BatchTargetExceptionCode(Exception exception) => exception switch
    {
        FileNotFoundException => 2,
        UnauthorizedAccessException => 8,
        _ => 3
    };

    private static Dictionary<string, object?> BatchFields(BatchAnalysisSummary summary) => new()
    {
        ["completed_at_utc"] = summary.CompletedAtUtc,
        ["succeeded"] = summary.Succeeded,
        ["failed"] = summary.Failed,
        ["skipped"] = summary.Skipped,
        ["exit_code"] = summary.ExitCode,
        ["items"] = summary.Items
    };

    private static void WriteSummaryAtomically(string summaryPath, BatchAnalysisSummary summary)
    {
        string destination = Path.GetFullPath(summaryPath);
        string? directory = Path.GetDirectoryName(destination);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("--summary must include a file name.");
        }

        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false)))
            {
                writer.Write(System.Text.Json.JsonSerializer.Serialize(BatchFields(summary), JsonDefaults.Options));
                writer.Flush();
                stream.Flush(true);
            }
            File.Move(temporary, destination, true);
        }
        catch
        {
            try { File.Delete(temporary); } catch { }
            throw;
        }
    }

    private static int SelfTest(Dictionary<string, string?> options, bool json)
    {
        string output = Get(options, "out") ?? Path.Combine(Environment.CurrentDirectory, "selftest");
        string sample = Environment.ProcessPath ?? typeof(CliApp).Assembly.Location;
        var runOptions = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["target"] = sample,
            ["duration"] = "5",
            ["out"] = output,
            ["format"] = "all",
            ["execute"] = "off"
        };
        int code = Run(runOptions, json);
        Console.WriteLine(code == 0 ? "[+] Selftest passed" : "[!] Selftest failed");
        return code == 0 ? 0 : 12;
    }

    private static int ListCases(Dictionary<string, string?> options)
    {
        var config = new MrtwConfigService().Load(Get(options, "config"));
        string workspace = Get(options, "workspace") ?? config.Workspace;
        var cases = new CaseService().List(workspace);
        if (cases.Count == 0)
        {
            Console.WriteLine("No cases found.");
            return 0;
        }

        Console.WriteLine("Case\tStatus\tStarted\tEvents");
        foreach (var summary in cases)
        {
            Console.WriteLine($"{summary.CaseName}\t{summary.Status}\t{summary.StartedAt:yyyy-MM-dd HH:mm:ss}\t{summary.EventCount}");
        }
        return 0;
    }

    private static int Open(Dictionary<string, string?> options, bool json)
    {
        string casePath = Required(options, "case");
        try
        {
            string directory = new CaseService().ResolveCaseDirectory(casePath);
            Log(json, "open", new Dictionary<string, object?> { ["case"] = directory }, $"[+] Case ready to open in MRTW.App: {directory}");
            return 0;
        }
        catch
        {
            return Error($"case not found: {casePath}", 10, json);
        }
    }

    private static Dictionary<string, string?> Parse(string[] args)
    {
        var options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            string token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            string key = token[2..];
            string? value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "true";
            options[key] = value;
        }
        return options;
    }

    private static string Required(Dictionary<string, string?> options, string key) =>
        Get(options, key) ?? throw new ArgumentException($"--{key} is required.");

    private static string? Get(Dictionary<string, string?> options, string key) =>
        options.TryGetValue(key, out string? value) && value != "true" ? value : null;

    private static bool GetOnOff(Dictionary<string, string?> options, string key, bool defaultValue)
    {
        string? value = Get(options, key);
        return value is null ? defaultValue : value.Equals("on", StringComparison.OrdinalIgnoreCase) || value.Equals("true", StringComparison.OrdinalIgnoreCase);
    }

    private static string InferType(string target, string cmd)
    {
        if (!string.IsNullOrWhiteSpace(cmd))
        {
            return "command";
        }
        return Path.GetExtension(target).ToLowerInvariant() switch
        {
            ".exe" => "exe",
            ".dll" => "dll",
            _ => "command"
        };
    }

    private static string BuildCommandLine(string target, string type, string runner, string? exportFunc) =>
        type == "dll" && runner == "rundll32"
            ? $"rundll32.exe \"{target}\",{exportFunc}"
            : $"\"{target}\"";

    private static ProfileDefaults ResolveProfile(MrtwConfig config, string? profileName)
    {
        string name = string.IsNullOrWhiteSpace(profileName) ? config.DefaultProfile : profileName;
        return config.Profiles.TryGetValue(name, out var profile) ? profile : MrtwConfig.Default.Profiles["full-capture"];
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static bool CanWrite(string path)
    {
        try
        {
            string probe = Path.Combine(path, ".mrtw-write-test");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void Log(bool json, string evt, Dictionary<string, object?> fields, string text)
    {
        if (json)
        {
            fields["level"] = "info";
            fields["event"] = evt;
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(fields, CliJsonOptions));
        }
        else
        {
            Console.WriteLine(text);
        }
    }

    private static int Error(string message, int code, bool json)
    {
        if (json)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { level = "error", message, code }, CliJsonOptions));
        }
        else
        {
            Console.Error.WriteLine("ERROR: " + message);
        }
        return code;
    }

    private static void Help()
    {
        Console.WriteLine("""
MRTW - Malware Runtime Timeline Workbench

Usage:
  mrtw version
  mrtw doctor
  mrtw static --target <path> --out <dir> --format html,json
  mrtw run --target <path> --duration 60 --out <dir> --format all
  mrtw run --target <path> --execute off --out <dir>
  mrtw run --target <path> --profile full-capture --privacy-mode on
  mrtw export --case <case.sqlite|case dir> --format html,csv,json --out <dir>
  mrtw etw-smoke --duration 3
  mrtw batch --input <dir> --out <dir> [--summary <path>]  (does not support --cmd)
  mrtw selftest --out <dir>
  mrtw list --workspace <dir>
  mrtw open --case <case.sqlite|case dir>
""");
    }

    private sealed record RunCompletion(string CaseId, string CaseOutput, int Events, int Processes);
}
