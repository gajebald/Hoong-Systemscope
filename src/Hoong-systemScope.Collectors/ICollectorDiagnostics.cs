using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors;

/// <summary>
/// Sink for problems a collector hits without being able to continue past
/// them.
/// </summary>
/// <remarks>
/// Missing privileges are routine rather than exceptional. Without elevation a
/// good part of <c>HKEY_LOCAL_MACHINE</c>, the service database and every other
/// user's hive are unreadable. A collector that gave up there would make the
/// tool useless for the standard-user case, so instead it records the gap and
/// keeps going, and the report says plainly which areas were not covered.
/// </remarks>
public interface ICollectorDiagnostics
{
    /// <summary>Records a non-fatal problem.</summary>
    void Report(ScanError scanError);
}

/// <summary>Collects diagnostics in memory. Safe for concurrent use.</summary>
public sealed class CollectorDiagnostics : ICollectorDiagnostics
{
    private readonly List<ScanError> _errors = [];
    private readonly object _gate = new();

    /// <summary>Everything reported so far.</summary>
    public IReadOnlyList<ScanError> Errors
    {
        get
        {
            lock (_gate)
            {
                return _errors.ToArray();
            }
        }
    }

    /// <inheritdoc />
    public void Report(ScanError scanError)
    {
        ArgumentNullException.ThrowIfNull(scanError);

        lock (_gate)
        {
            _errors.Add(scanError);
        }
    }
}
