using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Wpf;

/// <summary>
/// Colours a row by its risk level.
/// </summary>
/// <remarks>
/// The palette is deliberately restrained. Only Critical is red; High is amber
/// and everything below is neutral. A grid where most rows are coloured teaches
/// the reader to stop looking at the colour.
/// </remarks>
public sealed class RiskLevelBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Critical = Freeze(Color.FromRgb(0xB3, 0x1D, 0x1D));
    private static readonly SolidColorBrush High = Freeze(Color.FromRgb(0xB5, 0x6A, 0x00));
    private static readonly SolidColorBrush Medium = Freeze(Color.FromRgb(0x7A, 0x5C, 0x00));
    private static readonly SolidColorBrush Quiet = Freeze(Color.FromRgb(0x44, 0x44, 0x44));

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        RiskLevel.Critical => Critical,
        RiskLevel.High => High,
        RiskLevel.Medium => Medium,
        _ => Quiet,
    };

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("Risk colours are display only.");

    private static SolidColorBrush Freeze(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }
}

/// <summary>Maps a boolean onto visibility, collapsing rather than hiding.</summary>
public sealed class BooleanToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is true;

        if (parameter is string s && s.Equals("invert", StringComparison.OrdinalIgnoreCase))
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("Visibility is display only.");
}

/// <summary>Shows an element only when the bound value is not null.</summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is null ? Visibility.Collapsed : Visibility.Visible;

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("Visibility is display only.");
}
