using System.Security.Cryptography;
using System.Text;

var markers = new[]
{
    "https://analysis-probe.example.test/update",
    "http://telemetry.analysis-probe.example.test/beacon",
    "analysis-probe.example.test",
    @"HKCU\Software\MRTW\StaticAnalysisProbe",
    @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    @"C:\Users\Public\Documents\analysis-probe.dat",
    @"C:\ProgramData\MRTW\StaticAnalysisProbe\probe.bin",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File benign-probe.ps1",
    "cmd.exe /d /c echo MRTW static analysis probe",
    "DllRegisterServer",
    "StartStaticAnalysisProbe"
};

Console.WriteLine("MRTW StaticAnalysisProbe");
Console.WriteLine("This sample is benign and does not execute the marker commands.");

foreach (string marker in markers)
{
    byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(marker));
    Console.WriteLine($"{marker.Length:D3} {Convert.ToHexString(digest)[..12]}");
}
