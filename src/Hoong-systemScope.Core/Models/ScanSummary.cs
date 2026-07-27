namespace HoongSystemScope.Core.Models;

/// <summary>Aggregated counts for a completed scan.</summary>
public sealed record ScanSummary
{
    /// <summary>Total number of entries in the report.</summary>
    public required int TotalEntries { get; init; }

    /// <summary>Entry count per risk level.</summary>
    public IReadOnlyDictionary<RiskLevel, int> ByRiskLevel { get; init; } =
        new Dictionary<RiskLevel, int>();

    /// <summary>Entry count per category.</summary>
    public IReadOnlyDictionary<ScanCategory, int> ByCategory { get; init; } =
        new Dictionary<ScanCategory, int>();

    /// <summary>Entry count per signature status.</summary>
    public IReadOnlyDictionary<SignatureStatus, int> BySignatureStatus { get; init; } =
        new Dictionary<SignatureStatus, int>();

    /// <summary>Number of entries whose target file is missing.</summary>
    public int MissingFileCount { get; init; }

    /// <summary>Highest risk level present in the report.</summary>
    public RiskLevel HighestRiskLevel { get; init; }
}
