using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors;

/// <summary>One scanner module.</summary>
public interface IScanCollector
{
    /// <summary>Stable identifier, used on the command line and in reports.</summary>
    string Id { get; }

    /// <summary>Human readable description of what the collector covers.</summary>
    string Description { get; }

    /// <summary>Primary category the collector produces.</summary>
    ScanCategory Category { get; }

    /// <summary>
    /// True when the collector needs administrative rights to see everything.
    /// It still runs without them and reports the gap.
    /// </summary>
    bool RequiresElevation { get; }

    /// <summary>Collects entries. Implementations must not throw for expected access failures.</summary>
    IAsyncEnumerable<ScanEntry> CollectAsync(ScanContext context, CancellationToken cancellationToken);
}
