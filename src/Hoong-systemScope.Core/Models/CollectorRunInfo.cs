namespace HoongSystemScope.Core.Models;

/// <summary>Per collector bookkeeping for one scan.</summary>
public sealed record CollectorRunInfo
{
    /// <summary>Identifier of the collector.</summary>
    public required string CollectorId { get; init; }

    /// <summary>Primary category the collector produces.</summary>
    public required ScanCategory Category { get; init; }

    /// <summary>Number of entries the collector emitted.</summary>
    public required int EntryCount { get; init; }

    /// <summary>Wall clock duration of the collector run.</summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>True when the collector finished without raising an error.</summary>
    public required bool Succeeded { get; init; }

    /// <summary>True when the collector was skipped because it was not selected.</summary>
    public bool Skipped { get; init; }
}
