using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.Versioning;

namespace MRTW.Core;

public sealed class NetworkContainmentLease : IDisposable
{
    private readonly List<string> _ruleNames;
    private bool _disposed;

    internal NetworkContainmentLease(string mode, string message, List<string>? ruleNames = null)
    {
        Mode = mode;
        Message = message;
        _ruleNames = ruleNames ?? [];
    }

    public string Mode { get; }
    public string Message { get; }
    public bool Enforced => _ruleNames.Count > 0;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        foreach (string ruleName in _ruleNames)
        {
            NetworkContainmentService.DeleteRule(ruleName);
        }
    }
}

public static class NetworkContainmentService
{
    public static NetworkContainmentLease Apply(ExecutionProfile profile)
    {
        string mode = NormalizeMode(profile.NetworkMode);
        if (!profile.ExecuteTarget || mode == "observe")
        {
            return new NetworkContainmentLease(mode, profile.ExecuteTarget ? "Network traffic is observed but not blocked." : "Execution is disabled; containment was not required.");
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new InvalidOperationException($"Network mode '{mode}' requires Windows Firewall and cannot be enforced on this platform.");
        }
        if (!IsAdministrator())
        {
            throw new InvalidOperationException($"Network mode '{mode}' requires administrator privileges. Execution was refused because containment could not be enforced.");
        }

        string program = ResolveHostProgram(profile);
        if (mode == "block" && (!Path.IsPathFullyQualified(program) || !File.Exists(program)))
        {
            throw new InvalidOperationException($"Network mode '{mode}' could not resolve the executable host '{program}'. Execution was refused.");
        }

        string prefix = "MRTW-" + Guid.NewGuid().ToString("N");
        var rules = new List<string>();
        try
        {
            string outbound = prefix + "-out";
            AddRule(outbound, mode == "isolated" ? null : program, "out");
            rules.Add(outbound);
            if (mode == "isolated")
            {
                string inbound = prefix + "-in";
                AddRule(inbound, null, "in");
                rules.Add(inbound);
            }
            string scope = mode == "isolated" ? "all machine traffic for the duration of the analysis" : program;
            return new NetworkContainmentLease(mode, $"{mode} enforced for {scope}", rules);
        }
        catch
        {
            foreach (string rule in rules)
            {
                DeleteRule(rule);
            }
            throw;
        }
    }

    public static string NormalizeMode(string? mode) => (mode ?? "observe").Trim().ToLowerInvariant() switch
    {
        "" or "observe" or "on" => "observe",
        "block" or "off" => "block",
        "isolated" or "isolate" => "isolated",
        var unsupported => throw new ArgumentException($"Unsupported network mode '{unsupported}'. Use observe, block, or isolated.")
    };

    internal static string ResolveHostProgram(ExecutionProfile profile)
    {
        if (profile.TargetType.Equals("dll", StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(Environment.SystemDirectory, "rundll32.exe");
        }
        if (profile.TargetType.Equals("command", StringComparison.OrdinalIgnoreCase))
        {
            return Environment.GetEnvironmentVariable("COMSPEC") ?? Path.Combine(Environment.SystemDirectory, "cmd.exe");
        }
        return Path.GetFullPath(profile.TargetPath);
    }

    private static void AddRule(string name, string? program, string direction)
    {
        var arguments = new List<string>
        {
            "advfirewall", "firewall", "add", "rule",
            $"name={name}", $"dir={direction}", "action=block", "enable=yes", "profile=any"
        };
        if (!string.IsNullOrWhiteSpace(program))
        {
            arguments.Add($"program={program}");
        }
        var result = RunNetsh(arguments);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"Windows Firewall rule '{name}' could not be created: {result.Message}");
        }
    }

    internal static void DeleteRule(string name)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        _ = RunNetsh(["advfirewall", "firewall", "delete", "rule", $"name={name}"]);
    }

    private static (int ExitCode, string Message) RunNetsh(IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("netsh.exe could not be started.");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, (output + " " + error).Trim());
    }

    [SupportedOSPlatform("windows")]
    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
