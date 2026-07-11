using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
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
await RunLocalhostProbeAsync();
RunChildProcessProbe();

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

static async Task RunLocalhostProbeAsync()
{
    using var client = new TcpClient();
    try
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await client.ConnectAsync("127.0.0.1", 9, cts.Token);
    }
    catch
    {
        // Expected on most hosts. The goal is only a localhost connection attempt.
    }

    Console.WriteLine("localhost probe complete");
}

static void RunChildProcessProbe()
{
    using var process = Process.Start(new ProcessStartInfo
    {
        FileName = Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe",
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
