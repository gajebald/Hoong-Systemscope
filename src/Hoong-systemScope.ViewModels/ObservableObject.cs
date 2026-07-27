using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HoongSystemScope.ViewModels;

/// <summary>
/// Minimal change-notification base class.
/// </summary>
/// <remarks>
/// Hand-written rather than pulled from a MVVM toolkit. The view models need
/// exactly this much, and the project's dependency surface is part of what it
/// asks to be trusted on.
/// </remarks>
public abstract class ObservableObject : INotifyPropertyChanged
{
    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Raises <see cref="PropertyChanged"/> for the given property.</summary>
    protected void RaisePropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    /// <summary>Assigns a field and notifies when the value actually changed.</summary>
    /// <returns>True when the value changed.</returns>
    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        RaisePropertyChanged(propertyName);
        return true;
    }
}
