using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using MRTW.Core;

namespace MRTW.App;

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            EventSeverity.Critical => Brushes.Red,
            EventSeverity.High => new SolidColorBrush(Color.FromRgb(255, 123, 66)),
            EventSeverity.Medium => new SolidColorBrush(Color.FromRgb(255, 201, 71)),
            EventSeverity.Low => new SolidColorBrush(Color.FromRgb(88, 166, 255)),
            _ => new SolidColorBrush(Color.FromRgb(157, 195, 230))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class CategoryBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            EventCategory.Process => new SolidColorBrush(Color.FromRgb(47, 111, 228)),
            EventCategory.File => new SolidColorBrush(Color.FromRgb(78, 162, 58)),
            EventCategory.Registry => new SolidColorBrush(Color.FromRgb(201, 106, 23)),
            EventCategory.Dns => new SolidColorBrush(Color.FromRgb(35, 136, 149)),
            EventCategory.Network => new SolidColorBrush(Color.FromRgb(118, 80, 184)),
            EventCategory.Api => new SolidColorBrush(Color.FromRgb(181, 150, 46)),
            _ => new SolidColorBrush(Color.FromRgb(88, 107, 132))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class EmptyStringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.IsNullOrWhiteSpace(value as string) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}
