using System.Diagnostics;
using System.Text.Json;

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("SKIP ProbeTests requires Windows.");
    return 0;
}

string root = FindRepositoryRoot();
string safeProbe = Environment.GetEnvironmentVariable("MRTW_SAFE_PROBE_PATH")
    ?? Path.Combine(root, "test", "SafeRuntimeProbe", "bin", "Release", "net9.0", "SafeRuntimeProbe.exe");
if (!File.Exists(safeProbe))
    throw new FileNotFoundException("Build SafeRuntimeProbe first or set MRTW_SAFE_PROBE_PATH.", safeProbe);

string outputName = "mrtw-probe-observation-" + Guid.NewGuid().ToString("N") + ".json";
string output = Path.Combine(Path.GetTempPath(), "MRTW-Probe", "observations", outputName);
try
{
    using var process = Process.Start(new ProcessStartInfo
    {
        FileName = safeProbe,
        Arguments = Quote(outputName),
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    }) ?? throw new InvalidOperationException("SafeRuntimeProbe could not be started.");
    if (!process.WaitForExit(15_000))
    {
        process.Kill(true);
        throw new TimeoutException("SafeRuntimeProbe did not finish in 15 seconds.");
    }
    string stderr = process.StandardError.ReadToEnd();
    if (process.ExitCode != 0) throw new InvalidOperationException($"SafeRuntimeProbe failed ({process.ExitCode}): {stderr}");
    var observation = JsonSerializer.Deserialize<LocalhostObservation>(File.ReadAllText(output), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
        ?? throw new InvalidDataException("Probe did not produce a JSON observation.");
    Assert(observation.Endpoint == "127.0.0.1", "probe used a non-loopback endpoint");
    Assert(observation.TcpPort is > 0 and < 65536, "TCP port was invalid");
    Assert(observation.UdpPort is > 0 and < 65536, "UDP port was invalid");
    Assert(observation.HttpRequestLine == "GET /mrtw-safe-probe HTTP/1.1", "localhost HTTP request was not observed");
    Assert(observation.UdpPayload == "MRTW-safe-udp", "localhost UDP payload was not observed");
    Assert(observation.DnsAddresses.Count > 0 && observation.DnsAddresses.All(IsLoopback), "local-only hostname mapping returned a non-loopback address");
    Assert(observation.CleanupComplete, "probe did not report cleanup completion");
    Console.WriteLine("PASS SafeRuntimeProbe localhost HTTP/TCP, UDP, local-only mapping and cleanup observation");
}
finally
{
    if (File.Exists(output)) File.Delete(output);
}

string? nativeProbe = Environment.GetEnvironmentVariable("MRTW_NATIVE_SAFE_PROBE_PATH");
if (string.IsNullOrWhiteSpace(nativeProbe) || !File.Exists(nativeProbe))
{
    Console.WriteLine("SKIP native direct runner: set MRTW_NATIVE_SAFE_PROBE_PATH to an explicitly built benign probe.");
    return 0;
}
using (var native = Process.Start(new ProcessStartInfo { FileName = nativeProbe, UseShellExecute = false, CreateNoWindow = true })
       ?? throw new InvalidOperationException("Native probe could not be started."))
{
    if (!native.WaitForExit(10_000)) { native.Kill(true); throw new TimeoutException("Native probe timed out."); }
    Assert(native.ExitCode == 0, "native direct runner failed");
}
Console.WriteLine("PASS NativeSafeRuntimeProbe direct runner");
return 0;

static bool IsLoopback(string address) => System.Net.IPAddress.TryParse(address, out var parsed) && System.Net.IPAddress.IsLoopback(parsed);
static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
static string FindRepositoryRoot()
{
    for (var directory = new DirectoryInfo(Directory.GetCurrentDirectory()); directory is not null; directory = directory.Parent)
        if (File.Exists(Path.Combine(directory.FullName, "MRTW.sln"))) return directory.FullName;
    throw new DirectoryNotFoundException("MRTW.sln was not found above the current directory.");
}

internal sealed record LocalhostObservation(string Endpoint, int TcpPort, int UdpPort, string HttpRequestLine, string UdpPayload, IReadOnlyList<string> DnsAddresses, bool CleanupComplete);
