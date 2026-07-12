using System.Configuration;
using System.Data;
using System.Windows;

namespace MRTW.App;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
        if (!string.Equals(Environment.GetEnvironmentVariable("MRTW_GUI_TESTS"), "1", StringComparison.Ordinal)) return;
        string? target = ValueAfter(e.Args, "--smoke-target");
        string? casePath = ValueAfter(e.Args, "--smoke-case");
        string? exportRoot = ValueAfter(e.Args, "--smoke-export");
        try
        {
            if (!string.IsNullOrWhiteSpace(target)) await window.LoadSmokeTargetAsync(target);
            if (!string.IsNullOrWhiteSpace(casePath)) await window.LoadSmokeCaseAsync(casePath);
            if (!string.IsNullOrWhiteSpace(exportRoot)) await window.ExportSmokeCaseAsync(exportRoot);
        }
        catch (Exception ex)
        {
            MessageBox.Show(window, ex.Message, "MRTW GUI Smoke Setup", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string? ValueAfter(string[] args, string option)
    {
        int index = Array.FindIndex(args, a => string.Equals(a, option, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}

