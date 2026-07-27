namespace HoongSystemScope.Core.Models;

/// <summary>
/// Everything the caller can influence about a scan.
/// </summary>
/// <remarks>
/// There is no option that would make the tool modify the system: the scan is
/// read only by construction, not by configuration.
/// </remarks>
public sealed record ScanOptions
{
    /// <summary>
    /// Categories to collect. An empty set means every category.
    /// </summary>
    public IReadOnlySet<ScanCategory> Categories { get; init; } = new HashSet<ScanCategory>();

    /// <summary>
    /// Also inspect the hives of other users that are currently loaded.
    /// Unloaded profiles are never mounted, because mounting a hive would
    /// modify the system.
    /// </summary>
    public bool IncludeAllUsers { get; init; }

    /// <summary>Compute SHA-256 for every resolved executable.</summary>
    public bool ComputeHashes { get; init; } = true;

    /// <summary>Verify Authenticode signatures for every resolved executable.</summary>
    public bool VerifySignatures { get; init; } = true;

    /// <summary>Drop entries whose risk level is below this threshold from the report.</summary>
    public RiskLevel MinimumRiskLevel { get; init; } = RiskLevel.Informational;

    /// <summary>Upper bound for concurrent collector execution.</summary>
    public int MaxDegreeOfParallelism { get; init; } = Math.Max(2, Environment.ProcessorCount);

    /// <summary>Maximum size of a file that will be hashed. Larger files are skipped.</summary>
    public long MaxHashFileSizeBytes { get; init; } = 512L * 1024 * 1024;

    /// <summary>Default options.</summary>
    public static ScanOptions Default { get; } = new();

    /// <summary>True when <paramref name="category"/> should be collected.</summary>
    public bool IncludesCategory(ScanCategory category) =>
        Categories.Count == 0 || Categories.Contains(category);
}
