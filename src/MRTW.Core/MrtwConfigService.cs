using System.Globalization;

namespace MRTW.Core;

public sealed class MrtwConfigService
{
    public MrtwConfig Load(string? explicitPath = null)
    {
        foreach (string path in CandidatePaths(explicitPath))
        {
            if (File.Exists(path))
            {
                return Parse(File.ReadAllLines(path));
            }
        }

        return MrtwConfig.Default;
    }

    private static IEnumerable<string> CandidatePaths(string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            yield return explicitPath;
            yield break;
        }

        yield return Path.Combine(Environment.CurrentDirectory, "config.yaml");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MRTW", "config.yaml");
    }

    private static MrtwConfig Parse(string[] lines)
    {
        string workspace = MrtwConfig.Default.Workspace;
        string exports = MrtwConfig.Default.Exports;
        string defaultProfile = MrtwConfig.Default.DefaultProfile;
        string logFormat = MrtwConfig.Default.LogFormat;
        bool quiet = MrtwConfig.Default.Quiet;
        bool verbose = MrtwConfig.Default.Verbose;

        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            int colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            string key = line[..colon].Trim();
            string value = Unquote(line[(colon + 1)..].Trim());
            switch (key)
            {
                case "workspace":
                    workspace = value;
                    break;
                case "exports":
                    exports = value;
                    break;
                case "default_profile":
                    defaultProfile = value;
                    break;
                case "log_format":
                    logFormat = value;
                    break;
                case "quiet":
                    quiet = ParseBool(value);
                    break;
                case "verbose":
                    verbose = ParseBool(value);
                    break;
            }
        }

        return MrtwConfig.Default with
        {
            Workspace = Expand(workspace),
            Exports = Expand(exports),
            DefaultProfile = defaultProfile,
            LogFormat = logFormat,
            Quiet = quiet,
            Verbose = verbose
        };
    }

    private static bool ParseBool(string value) => bool.TryParse(value, out bool parsed) && parsed;

    private static string Unquote(string value) => value.Trim().Trim('"').Trim('\'');

    private static string Expand(string value)
    {
        string expanded = Environment.ExpandEnvironmentVariables(value);
        return Path.IsPathRooted(expanded) ? expanded : Path.GetFullPath(expanded);
    }
}

