using System.Diagnostics;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

[assembly: SupportedOSPlatform("windows")]

Console.WriteLine("MRTW SafeRuntimeProbe started.");
Console.WriteLine("This program is benign and only touches temporary MRTW-Probe resources.");
Thread.Sleep(3000);

string root = Path.Combine(Path.GetTempPath(), "MRTW-Probe");
Directory.CreateDirectory(root);

RunFileProbe(root);
RunRegistryProbe();
RunDllLoadProbe();
RunComProbe();
var networkObservation = await RunLocalhostProbeAsync();
RunChildProcessProbe();

string observationName = args.Length == 1 ? args[0] : "network-observation.json";
if (!string.Equals(observationName, Path.GetFileName(observationName), StringComparison.Ordinal) || !observationName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
    throw new ArgumentException("Observation argument must be a JSON file name without a path.");
string observationDirectory = Path.Combine(root, "observations");
Directory.CreateDirectory(observationDirectory);
string observationPath = Path.Combine(observationDirectory, observationName);
await using (var output = new FileStream(observationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
await using (var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true }))
{
    JsonSerializer.Serialize(writer, networkObservation);
}
Console.WriteLine($"network observation: {observationPath}");

Console.WriteLine("MRTW SafeRuntimeProbe completed.");

static void RunFileProbe(string root)
{
    string path = Path.Combine(root, "probe.txt");
    string moved = Path.Combine(root, "probe-renamed.txt");

    IntPtr handle = NativeMethods.CreateFileW(
        path,
        NativeMethods.GenericWrite,
        NativeMethods.FileShareRead,
        IntPtr.Zero,
        NativeMethods.CreateAlways,
        NativeMethods.FileAttributeNormal,
        IntPtr.Zero);

    if (handle != NativeMethods.InvalidHandleValue)
    {
        byte[] data = Encoding.UTF8.GetBytes("MRTW SafeRuntimeProbe file create and write\n");
        NativeMethods.WriteFile(handle, data, data.Length, out _, IntPtr.Zero);
        NativeMethods.CloseHandle(handle);
    }

    if (File.Exists(moved))
    {
        NativeMethods.DeleteFileW(moved);
    }

    NativeMethods.MoveFileExW(path, moved, NativeMethods.MoveFileReplaceExisting);
    NativeMethods.DeleteFileW(moved);
    Console.WriteLine("file probe complete");
}

static void RunRegistryProbe()
{
    const string subKey = @"Software\MRTW\Probe";
    int status = NativeMethods.RegCreateKeyExW(
        NativeMethods.HkeyCurrentUser,
        subKey,
        0,
        null,
        0,
        NativeMethods.KeySetValue,
        IntPtr.Zero,
        out UIntPtr key,
        out _);

    if (status == 0)
    {
        byte[] value = Encoding.Unicode.GetBytes(DateTimeOffset.UtcNow.ToString("O") + "\0");
        NativeMethods.RegSetValueExW(key, "LastRunUtc", 0, NativeMethods.RegSz, value, value.Length);
        NativeMethods.RegCloseKey(key);
    }

    NativeMethods.RegDeleteKeyW(NativeMethods.HkeyCurrentUser, subKey);
    Registry.CurrentUser.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
    Console.WriteLine("registry probe complete");
}

static void RunDllLoadProbe()
{
    IntPtr module = NativeMethods.LoadLibraryW("kernel32.dll");
    if (module != IntPtr.Zero)
    {
        NativeMethods.FreeLibrary(module);
    }

    Console.WriteLine("dll load probe complete");
}

static void RunComProbe()
{
    int hr = NativeMethods.CoInitializeEx(IntPtr.Zero, 0x2);
    if (hr >= 0)
    {
        NativeMethods.CoUninitialize();
    }

    Console.WriteLine("com probe complete");
}

static async Task<LocalhostObservation> RunLocalhostProbeAsync()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    int tcpPort = ((IPEndPoint)listener.LocalEndpoint).Port;
    Task<string> server = Task.Run(async () =>
    {
        using TcpClient accepted = await listener.AcceptTcpClientAsync();
        using var reader = new StreamReader(accepted.GetStream(), Encoding.ASCII, leaveOpen: true);
        string request = await reader.ReadLineAsync() ?? string.Empty;
        byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await accepted.GetStream().WriteAsync(response);
        return request;
    });
    using var client = new TcpClient();
    await client.ConnectAsync(IPAddress.Loopback, tcpPort);
    byte[] requestBytes = Encoding.ASCII.GetBytes("GET /mrtw-safe-probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    await client.GetStream().WriteAsync(requestBytes);
    byte[] responseBuffer = new byte[128];
    _ = await client.GetStream().ReadAsync(responseBuffer);
    string requestLine = await server.WaitAsync(TimeSpan.FromSeconds(2));

    using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    int udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
    using var udpClient = new UdpClient(AddressFamily.InterNetwork);
    byte[] udpPayload = Encoding.ASCII.GetBytes("MRTW-safe-udp");
    await udpClient.SendAsync(udpPayload, udpPayload.Length, new IPEndPoint(IPAddress.Loopback, udpPort));
    UdpReceiveResult udpResult = await udpServer.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2));

    // Do not call the system resolver: a broken hosts/DNS configuration could emit external traffic.
    // The probe validates MRTW's localhost-only endpoint handling with explicit loopback addresses.
    IPAddress[] localhostAddresses = [IPAddress.Loopback, IPAddress.IPv6Loopback];
    var observation = new LocalhostObservation("127.0.0.1", tcpPort, udpPort, requestLine,
        Encoding.ASCII.GetString(udpResult.Buffer), localhostAddresses.Select(address => address.ToString()).ToArray(), true);
    Console.WriteLine("localhost HTTP/TCP and UDP probe complete; local-only address mapping was used.");
    return observation;
}

static void RunChildProcessProbe()
{
    using var process = Process.Start(new ProcessStartInfo
    {
        FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
        Arguments = "/d /c echo MRTW SafeRuntimeProbe child process",
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    });

    process?.WaitForExit(3000);
    Console.WriteLine("child process probe complete");
}

internal static partial class NativeMethods
{
    internal const uint GenericWrite = 0x40000000;
    internal const uint FileShareRead = 0x00000001;
    internal const uint CreateAlways = 2;
    internal const uint FileAttributeNormal = 0x00000080;
    internal const uint MoveFileReplaceExisting = 0x00000001;
    internal const uint KeySetValue = 0x0002;
    internal const uint RegSz = 1;
    internal static readonly IntPtr InvalidHandleValue = new(-1);
    internal static readonly UIntPtr HkeyCurrentUser = new(0x80000001u);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool WriteFile(IntPtr file, byte[] buffer, int bytesToWrite, out int bytesWritten, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool DeleteFileW(string fileName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int RegCreateKeyExW(UIntPtr key, string subKey, int reserved, string? keyClass, int options, uint samDesired, IntPtr securityAttributes, out UIntPtr resultKey, out int disposition);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int RegSetValueExW(UIntPtr key, string valueName, int reserved, uint type, byte[] data, int dataSize);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int RegDeleteKeyW(UIntPtr key, string subKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegCloseKey(UIntPtr key);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr LoadLibraryW(string fileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool FreeLibrary(IntPtr module);

    [DllImport("ole32.dll")]
    internal static extern int CoInitializeEx(IntPtr reserved, uint coInit);

    [DllImport("ole32.dll")]
    internal static extern void CoUninitialize();
}

internal sealed record LocalhostObservation(string Endpoint, int TcpPort, int UdpPort, string HttpRequestLine, string UdpPayload, IReadOnlyList<string> DnsAddresses, bool CleanupComplete);
