namespace HoongSystemScope.Core.Models;

/// <summary>
/// The complete outcome of one scan: entries, gaps and bookkeeping.
/// </summary>
/// <remarks>
/// This is also the on-disk baseline format. Serialising and re-reading a
/// <see cref="ScanResult"/> must round-trip losslessly, which is why every
/// nested type is a plain immutable record.
/// </remarks>
public sealed record ScanResult
{
    /// <summary>Schema version of the serialised form.</summary>
    public required int SchemaVersion { get; init; }

    /// <summary>Version of the tool that produced the scan.</summary>
    public required string ToolVersion { get; init; }

    /// <summary>The scanned machine.</summary>
    public required MachineInfo Machine { get; init; }

    /// <summary>When the scan started.</summary>
    public required DateTimeOffset StartedAtUtc { get; init; }

    /// <summary>When the scan finished.</summary>
    public required DateTimeOffset CompletedAtUtc { get; init; }

    /// <summary>All findings.</summary>
    public IReadOnlyList<ScanEntry> Entries { get; init; } = Array.Empty<ScanEntry>();

    /// <summary>Areas that could not be read and other non-fatal problems.</summary>
    public IReadOnlyList<ScanError> Errors { get; init; } = Array.Empty<ScanError>();

    /// <summary>Per collector bookkeeping.</summary>
    public IReadOnlyList<CollectorRunInfo> Collectors { get; init; } = Array.Empty<CollectorRunInfo>();

    /// <summary>Aggregated counts.</summary>
    public ScanSummary? Summary { get; init; }

    /// <summary>The current schema version written by this build.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>True when at least one collector reported an error.</summary>
    public bool IsPartial => Errors.Any(e => e.Severity == ScanErrorSeverity.Error);
}
