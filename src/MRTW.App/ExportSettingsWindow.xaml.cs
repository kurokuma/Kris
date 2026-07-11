using System.Windows;

namespace MRTW.App;

public partial class ExportSettingsWindow : Window
{
    public ExportSettingsWindow(ExportSettings settings)
    {
        InitializeComponent();
        Settings = settings;
        DataContext = Settings;
    }

    public ExportSettings Settings { get; }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
