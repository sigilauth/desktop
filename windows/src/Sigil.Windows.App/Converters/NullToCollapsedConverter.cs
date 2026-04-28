using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Sigil.Windows.App.Views;

/// <summary>
/// Converts null to Collapsed and non-null to Visible.
/// Used to hide UI elements when data is missing.
/// </summary>
public sealed class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value is null ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotImplementedException();
    }
}
