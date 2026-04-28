using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Sigil.Windows.App.Views;

/// <summary>
/// Converts true to Collapsed and false to Visible.
/// Used to show/hide UI elements based on inverted boolean properties.
/// </summary>
public sealed class BoolNegationConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is bool boolValue)
        {
            return boolValue ? Visibility.Collapsed : Visibility.Visible;
        }

        return Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotImplementedException();
    }
}
