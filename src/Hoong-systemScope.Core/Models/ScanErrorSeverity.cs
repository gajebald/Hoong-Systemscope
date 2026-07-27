namespace HoongSystemScope.Core.Models;

/// <summary>Severity of a non-fatal problem encountered during a scan.</summary>
public enum ScanErrorSeverity
{
    /// <summary>Purely informational, for example a source that does not exist on this machine.</summary>
    Information = 0,

    /// <summary>A part of a collector's scope could not be read; the scan result is incomplete.</summary>
    Warning,

    /// <summary>A collector failed entirely.</summary>
    Error,
}
