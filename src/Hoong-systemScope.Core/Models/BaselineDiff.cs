namespace HoongSystemScope.Core.Models;

/// <summary>A single field that differs between two versions of the same entry.</summary>
public sealed record FieldChange
{
    /// <summary>Name of the changed field, for example <c>Sha256</c>.</summary>
    public required string Field { get; init; }

    /// <summary>Value in the older scan.</summary>
    public string? OldValue { get; init; }

    /// <summary>Value in the newer scan.</summary>
    public string? NewValue { get; init; }
}

/// <summary>One entry as seen by the baseline comparison.</summary>
public sealed record BaselineEntryChange
{
    /// <summary>Stable identity shared by both sides.</summary>
    public required string Id { get; init; }

    /// <summary>How the entry changed.</summary>
    public required BaselineChangeKind Kind { get; init; }

    /// <summary>The entry as it appeared in the older scan, if present.</summary>
    public ScanEntry? Before { get; init; }

    /// <summary>The entry as it appeared in the newer scan, if present.</summary>
    public ScanEntry? After { get; init; }

    /// <summary>The individual fields that differ. Only populated for <see cref="BaselineChangeKind.Modified"/>.</summary>
    public IReadOnlyList<FieldChange> Changes { get; init; } = Array.Empty<FieldChange>();
}

/// <summary>The result of comparing two scans.</summary>
public sealed record BaselineDiff
{
    /// <summary>When the older scan was taken.</summary>
    public required DateTimeOffset BaselineTakenAtUtc { get; init; }

    /// <summary>When the newer scan was taken.</summary>
    public required DateTimeOffset CurrentTakenAtUtc { get; init; }

    /// <summary>Entries only present in the newer scan.</summary>
    public IReadOnlyList<BaselineEntryChange> Added { get; init; } = Array.Empty<BaselineEntryChange>();

    /// <summary>Entries only present in the older scan.</summary>
    public IReadOnlyList<BaselineEntryChange> Removed { get; init; } = Array.Empty<BaselineEntryChange>();

    /// <summary>Entries present in both scans with at least one differing field.</summary>
    public IReadOnlyList<BaselineEntryChange> Modified { get; init; } = Array.Empty<BaselineEntryChange>();

    /// <summary>Number of entries that are identical in both scans.</summary>
    public int UnchangedCount { get; init; }

    /// <summary>True when nothing at all changed.</summary>
    public bool IsEmpty => Added.Count == 0 && Removed.Count == 0 && Modified.Count == 0;
}
