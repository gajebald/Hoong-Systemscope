namespace HoongSystemScope.ViewModels;

/// <summary>
/// An <see cref="IProgress{T}"/> that invokes its handler inline.
/// </summary>
/// <remarks>
/// <see cref="Progress{T}"/> posts to the synchronization context captured at
/// construction, so a report raised during an operation can land after that
/// operation has already completed. For a progress line that is merely
/// cosmetic, that asynchrony buys nothing and costs testability.
/// </remarks>
/// <typeparam name="T">Type of the progress value.</typeparam>
public sealed class SynchronousProgress<T> : IProgress<T>
{
    private readonly Action<T> _handler;

    /// <summary>Creates a progress sink around a handler.</summary>
    public SynchronousProgress(Action<T> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handler = handler;
    }

    /// <inheritdoc />
    public void Report(T value) => _handler(value);
}
