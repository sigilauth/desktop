using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Sigil.Windows.App.Views;

/// <summary>
/// Converts non-empty string to Visible and empty/null to Collapsed.
/// Used to show error messages only when present.
/// </summary>
public sealed class StringNotEmptyConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is string str && !string.IsNullOrEmpty(str))
        {
            return Visibility.Visible;
        }

        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotImplementedException();
    }
}
