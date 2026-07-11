using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace MRTW.Core;

public sealed class HookPipeServer : IAsyncDisposable
{
    private readonly CancellationTokenSource _cancellation = new();
    private readonly ConcurrentQueue<string> _rawLines = new();
    private Task? _serverTask;

    public string PipeName { get; } = "mrtw-hook-" + Guid.NewGuid().ToString("N");

    public string FullPipeName => @"\\.\pipe\" + PipeName;

    public void Start()
    {
        _serverTask = Task.Run(ServerLoopAsync);
    }

    public IReadOnlyList<TimelineEvent> DrainEvents(DateTimeOffset startedAt, ref int nextId)
    {
        var events = new List<TimelineEvent>();
        while (_rawLines.TryDequeue(out string? line))
        {
            events.Add(ToTimelineEvent(line, startedAt, nextId++));
        }

        return events;
    }

    public async ValueTask DisposeAsync()
    {
        _cancellation.Cancel();
        if (_serverTask is not null)
        {
            try
            {
                await _serverTask.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Shutdown should not mask the analysis result.
            }
        }

        _cancellation.Dispose();
    }

    private async Task ServerLoopAsync()
    {
        while (!_cancellation.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                await server.WaitForConnectionAsync(_cancellation.Token);
                using var reader = new StreamReader(server, Encoding.UTF8, leaveOpen: true);
                while (!_cancellation.IsCancellationRequested && server.IsConnected)
                {
                    string? line = await reader.ReadLineAsync(_cancellation.Token);
                    if (line is null)
                    {
                        break;
                    }

                    _rawLines.Enqueue(line);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                await Task.Delay(100, _cancellation.Token).ContinueWith(_ => { });
            }
        }
    }

    private static TimelineEvent ToTimelineEvent(string raw, DateTimeOffset startedAt, int id)
    {
        try
        {
            using var document = JsonDocument.Parse(raw);
            var root = document.RootElement;
            string categoryText = GetString(root, "category", "API");
            string action = GetString(root, "action", GetString(root, "event", "Hook Event"));
            int pid = GetInt(root, "pid", 0);
            string process = pid == 0 ? "hook" : "pid-" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture);
            string obj = GetObjectValue(root);
            string summary = $"{action} {obj}".Trim();
            EventCategory category = Enum.TryParse<EventCategory>(categoryText, true, out var parsed) ? parsed : EventCategory.Api;
            EventSeverity severity = category is EventCategory.Credential or EventCategory.Registry ? EventSeverity.High : EventSeverity.Medium;
            var technique = MapTechnique(category, action, obj, root);
            return new TimelineEvent(id, DateTimeOffset.Now - startedAt, process, pid, category, action, obj, summary, severity, "Hook", raw, technique.Id, technique.Name, technique.Confidence);
        }
        catch
        {
            return new TimelineEvent(id, DateTimeOffset.Now - startedAt, "hook", 0, EventCategory.Api, "Hook Event", raw, raw, EventSeverity.Low, "Hook", raw);
        }
    }

    private static (string Id, string Name, string Confidence) MapTechnique(EventCategory category, string action, string obj, JsonElement root)
    {
        if (action is "VirtualAllocEx" or "WriteProcessMemory" or "CreateRemoteThread" or "QueueUserAPC" or "SetThreadContext" or "ResumeThread")
        {
            return ("T1055", "Process Injection", "High");
        }

        if (action is "CreateProcessW" or "CreateProcessA")
        {
            string commandLine = GetString(root, "command_line", string.Empty);
            string app = GetString(root, "application", string.Empty);
            string combined = app + " " + commandLine;
            if (ContainsAny(combined, "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec", "installutil", "wmic", "schtasks", "vssadmin", "bcdedit", "curl", "wget"))
            {
                return ("T1059", "Command and Scripting Interpreter", "Medium");
            }

            return ("T1106", "Native API", "Low");
        }

        if (action is "ShellExecuteW" or "ShellExecuteA" or "ShellExecuteExW")
        {
            string combined = GetString(root, "verb", string.Empty) + " " + GetString(root, "file", string.Empty) + " " + GetString(root, "parameters", string.Empty);
            if (ContainsAny(combined, "runas"))
            {
                return ("T1548.002", "Bypass User Account Control", "Medium");
            }

            if (ContainsAny(combined, "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec", "installutil", "wmic", "schtasks", "vssadmin", "bcdedit", "curl", "wget"))
            {
                return ("T1059", "Command and Scripting Interpreter", "Medium");
            }
        }

        if (category == EventCategory.Module || action is "LoadLibraryW" or "LoadLibraryExW" or "LdrLoadDll")
        {
            if (ContainsAny(obj, "\\temp\\", "\\appdata\\", "\\programdata\\", "\\downloads\\") || !obj.Contains('\\'))
            {
                return ("T1574.002", "DLL Side-Loading", "Medium");
            }

            return ("T1106", "Native API", "Low");
        }

        if (action is "CreateToolhelp32Snapshot" or "Process32FirstW" or "Process32NextW" or "EnumProcesses")
        {
            return ("T1057", "Process Discovery", "Medium");
        }

        if (action is "EnumServicesStatusExW")
        {
            return ("T1007", "System Service Discovery", "Medium");
        }

        if (action is "OpenSCManagerW" or "OpenServiceW" or "StartServiceW" or "ControlService" or "DeleteService")
        {
            return ("T1569.002", "Service Execution", action is "StartServiceW" or "DeleteService" ? "High" : "Medium");
        }

        if (action == "NtLoadDriver")
        {
            return ("T1547.006", "Kernel Modules and Extensions", "High");
        }

        if (action is "FindFirstFileW" or "FindNextFileW")
        {
            return ("T1083", "File and Directory Discovery", "Medium");
        }

        if (action is "RegEnumKeyExW" or "RegEnumValueW")
        {
            return ("T1012", "Query Registry", "Medium");
        }

        if (action is "OpenProcessToken" or "AdjustTokenPrivileges" or "DuplicateTokenEx" or "ImpersonateLoggedOnUser")
        {
            return ("T1134", "Access Token Manipulation", "High");
        }

        if (action is "CoCreateInstance" or "CoCreateInstanceEx" or "CoGetClassObject" or "CLSIDFromProgID" or "CLSIDFromString")
        {
            string combined = obj + " " + GetString(root, "prog_id", string.Empty) + " " + GetString(root, "clsid", string.Empty);
            if (ContainsAny(combined, "WbemScripting", "SWbemLocator", "{4590F811-1D3A-11D0-891F-00AA004B2E24}", "{76A64158-CB41-11D1-8B02-00600806D9B6}"))
            {
                return ("T1047", "Windows Management Instrumentation", "High");
            }

            return ("T1559.001", "Component Object Model", "Medium");
        }

        if (category == EventCategory.Network || category == EventCategory.Dns || action is "WinHttpSendRequest" or "HttpSendRequestW" or "connect" or "WSAConnect")
        {
            return ("T1071", "Application Layer Protocol", "Medium");
        }

        if (action is "InternetSetOptionW" or "WinHttpSetOption")
        {
            return ("T1090", "Proxy", "Medium");
        }

        if (action is "GetAdaptersAddresses" or "GetComputerNameW" or "GetUserNameW")
        {
            return ("T1082", "System Information Discovery", "Low");
        }

        if (action is "GetSystemFirmwareTable")
        {
            return ("T1497", "Virtualization/Sandbox Evasion", "Medium");
        }

        if (category == EventCategory.Credential || action is "CryptUnprotectData" or "CredReadW" or "MiniDumpWriteDump")
        {
            return ("T1003", "OS Credential Dumping", action == "MiniDumpWriteDump" ? "High" : "Medium");
        }

        if (category == EventCategory.Registry || action.StartsWith("Reg", StringComparison.OrdinalIgnoreCase) || action is "CreateServiceW" or "ChangeServiceConfigW")
        {
            return ("T1547", "Boot or Logon Autostart Execution", "Medium");
        }

        if (action is "IsDebuggerPresent" or "CheckRemoteDebuggerPresent" or "NtQueryInformationProcess" or "Sleep" or "SleepEx" or "GetTickCount" or "QueryPerformanceCounter")
        {
            return ("T1497", "Virtualization/Sandbox Evasion", "Medium");
        }

        if (action is "SetUnhandledExceptionFilter" or "AddVectoredExceptionHandler" or "AddVectoredContinueHandler" or "OutputDebugStringW" or "GetThreadContext")
        {
            return ("T1622", "Debugger Evasion", "Medium");
        }

        if (action is "AmsiScanBuffer" or "EtwEventWrite" or "VirtualProtect")
        {
            return ("T1562.001", "Disable or Modify Tools", "Medium");
        }

        if (action is "CryptEncrypt" or "BCryptEncrypt" or "BCryptGenerateSymmetricKey" or "CryptGenRandom")
        {
            return ("T1486", "Data Encrypted for Impact", "Low");
        }

        if (action is "OpenClipboard" or "GetClipboardData" or "SetClipboardData")
        {
            return ("T1115", "Clipboard Data", "Medium");
        }

        if (action is "BitBlt" or "GetDC" or "CreateCompatibleBitmap")
        {
            return ("T1113", "Screen Capture", "Medium");
        }

        if (action is "GetAsyncKeyState" or "GetKeyState" or "SetWindowsHookExW")
        {
            return ("T1056.001", "Keylogging", "Medium");
        }

        if (action is "CreateMutexW" or "OpenMutexW" or "CreateNamedPipeW" or "ConnectNamedPipe" or "CallNamedPipeW" or "CreateFileMappingW" or "MapViewOfFile")
        {
            return ("T1559", "Inter-Process Communication", "Low");
        }

        if (category == EventCategory.File && ContainsAny(action, "Delete", "Move", "Write", "SetFileInformation"))
        {
            return ("T1486", "Data Encrypted for Impact", "Low");
        }

        return (string.Empty, string.Empty, string.Empty);
    }

    private static bool ContainsAny(string value, params string[] needles) =>
        needles.Any(n => value.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static string GetObjectValue(JsonElement root)
    {
        foreach (string name in new[] { "endpoint", "query", "node_name", "server", "path", "value_name", "command_line", "object", "application", "file", "parameters", "proc_name", "target_name", "service_name", "binary_path", "new_path", "mutex_name", "pipe_name", "mapping_name", "module_name", "dll_name", "content_name", "clipboard_format", "prog_id", "clsid", "clsid_text", "driver_service", "message" })
        {
            string value = GetString(root, name, string.Empty);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return GetString(root, "event", "hook");
    }

    private static string GetString(JsonElement root, string name, string fallback)
    {
        return root.TryGetProperty(name, out var value) ? Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? fallback : fallback;
    }

    private static int GetInt(JsonElement root, string name, int fallback)
    {
        return root.TryGetProperty(name, out var value) && value.TryGetInt32(out int parsed) ? parsed : fallback;
    }
}

public sealed class NativeHookLauncher
{
    public bool IsAvailable => File.Exists(InjectorPath) && File.Exists(HookDllPath);

    public string InjectorPath { get; }

    public string HookDllPath { get; }

    public NativeHookLauncher(string? baseDirectory = null)
    {
        string root = baseDirectory ?? AppContext.BaseDirectory;
        InjectorPath = Path.Combine(root, "native", "injector_x64.exe");
        HookDllPath = Path.Combine(root, "native", "hook_x64.dll");
    }

    public ProcessStartInfo CreateStartInfo(ExecutionProfile profile, string pipeName)
    {
        string commandLine = profile.TargetType.Equals("command", StringComparison.OrdinalIgnoreCase)
            ? profile.CommandLine
            : $"\"{profile.TargetPath}\"";

        var startInfo = new ProcessStartInfo
        {
            FileName = InjectorPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("--target");
        startInfo.ArgumentList.Add(profile.TargetPath);
        startInfo.ArgumentList.Add("--cmd");
        startInfo.ArgumentList.Add(commandLine);
        startInfo.ArgumentList.Add("--working-dir");
        startInfo.ArgumentList.Add(profile.WorkingDirectory);
        startInfo.ArgumentList.Add("--hook");
        startInfo.ArgumentList.Add(HookDllPath);
        startInfo.ArgumentList.Add("--pipe");
        startInfo.ArgumentList.Add(pipeName);
        return startInfo;
    }
}
