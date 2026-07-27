namespace HoongSystemScope.Core.Models;

/// <summary>How an entry changed between two scans.</summary>
public enum BaselineChangeKind
{
    /// <summary>Present in both scans with identical tracked fields.</summary>
    Unchanged = 0,

    /// <summary>Only present in the newer scan.</summary>
    Added,

    /// <summary>Only present in the older scan.</summary>
    Removed,

    /// <summary>Present in both scans but at least one tracked field differs.</summary>
    Modified,
}
