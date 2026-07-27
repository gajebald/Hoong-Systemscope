namespace HoongSystemScope.Core.Models;

/// <summary>
/// A problem that occurred during a scan without aborting it.
/// </summary>
/// <remarks>
/// Missing privileges are the common case: without elevation a large part of
/// <c>HKEY_LOCAL_MACHINE</c> and most other users' hives are unreadable. Rather
/// than failing, the affected collector records the gap here so the report can
/// state honestly which areas were not covered.
/// </remarks>
public sealed record ScanError
{
    /// <summary>Collector that reported the problem.</summary>
    public required string CollectorId { get; init; }

    /// <summary>How badly the result is affected.</summary>
    public required ScanErrorSeverity Severity { get; init; }

    /// <summary>Human readable description.</summary>
    public required string Message { get; init; }

    /// <summary>The registry key, directory or other source that could not be read.</summary>
    public string? Location { get; init; }

    /// <summary>
    /// Type name of the underlying exception, if any. Full stack traces are
    /// never exported: they add no diagnostic value here and leak local paths.
    /// </summary>
    public string? ExceptionType { get; init; }
}
