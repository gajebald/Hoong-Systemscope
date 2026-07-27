using System.Windows.Input;

namespace HoongSystemScope.ViewModels;

/// <summary>A command backed by delegates.</summary>
public sealed class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    /// <summary>Creates a command.</summary>
    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        ArgumentNullException.ThrowIfNull(execute);

        _execute = execute;
        _canExecute = canExecute;
    }

    /// <inheritdoc />
    public event EventHandler? CanExecuteChanged;

    /// <inheritdoc />
    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

    /// <inheritdoc />
    public void Execute(object? parameter) => _execute();

    /// <summary>Asks the UI to re-query <see cref="CanExecute"/>.</summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>
/// A command backed by an asynchronous delegate.
/// </summary>
/// <remarks>
/// While the operation runs the command reports that it cannot execute, so a
/// second scan cannot be started on top of the first by double-clicking.
/// </remarks>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _isRunning;

    /// <summary>Creates a command.</summary>
    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        ArgumentNullException.ThrowIfNull(execute);

        _execute = execute;
        _canExecute = canExecute;
    }

    /// <inheritdoc />
    public event EventHandler? CanExecuteChanged;

    /// <summary>True while the operation is running.</summary>
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            _isRunning = value;
            RaiseCanExecuteChanged();
        }
    }

    /// <inheritdoc />
    public bool CanExecute(object? parameter) => !IsRunning && (_canExecute?.Invoke() ?? true);

    /// <inheritdoc />
    public async void Execute(object? parameter) => await ExecuteAsync();

    /// <summary>Runs the operation, guarding against re-entry.</summary>
    public async Task ExecuteAsync()
    {
        if (IsRunning)
        {
            return;
        }

        IsRunning = true;

        try
        {
            // No ConfigureAwait(false): the finally block raises
            // CanExecuteChanged, which the UI must observe on its own thread.
            await _execute();
        }
        finally
        {
            IsRunning = false;
        }
    }

    /// <summary>Asks the UI to re-query <see cref="CanExecute"/>.</summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
