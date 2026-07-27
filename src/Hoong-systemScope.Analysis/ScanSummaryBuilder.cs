using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis;

/// <summary>Aggregates a scored entry list into a <see cref="ScanSummary"/>.</summary>
public static class ScanSummaryBuilder
{
    /// <summary>Builds the summary.</summary>
    public static ScanSummary Build(IReadOnlyList<ScanEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        return new ScanSummary
        {
            TotalEntries = entries.Count,
            ByRiskLevel = entries
                .GroupBy(e => e.RiskLevel)
                .ToDictionary(g => g.Key, g => g.Count()),
            ByCategory = entries
                .GroupBy(e => e.Category)
                .ToDictionary(g => g.Key, g => g.Count()),
            BySignatureStatus = entries
                .GroupBy(e => e.SignatureStatus)
                .ToDictionary(g => g.Key, g => g.Count()),
            MissingFileCount = entries.Count(e => e.FileExists == false),
            HighestRiskLevel = entries.Count == 0 ? RiskLevel.Informational : entries.Max(e => e.RiskLevel),
        };
    }
}
