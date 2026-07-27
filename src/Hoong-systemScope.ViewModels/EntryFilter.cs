using HoongSystemScope.Core.Models;

namespace HoongSystemScope.ViewModels;

/// <summary>
/// Decides which findings the grid shows.
/// </summary>
/// <remarks>
/// Deliberately a plain, immutable value with a pure <see cref="Matches"/>
/// method rather than logic sprinkled through the view model. Filtering is the
/// part of a diagnostic viewer that quietly decides what the user does and does
/// not get to see, so it is worth having somewhere it can be tested directly.
/// </remarks>
public sealed record EntryFilter
{
    /// <summary>Hide entries below this risk level.</summary>
    public RiskLevel MinimumRiskLevel { get; init; } = RiskLevel.Informational;

    /// <summary>Show only these categories. Empty means all of them.</summary>
    public IReadOnlySet<ScanCategory> Categories { get; init; } = new HashSet<ScanCategory>();

    /// <summary>Free-text search across name, path, publisher and command line.</summary>
    public string? SearchText { get; init; }

    /// <summary>Show only entries whose target file is missing.</summary>
    public bool OnlyMissingFiles { get; init; }

    /// <summary>Show only entries that carry no trusted signature.</summary>
    public bool OnlyUntrusted { get; init; }

    /// <summary>A filter that hides nothing.</summary>
    public static EntryFilter None { get; } = new();

    /// <summary>True when this filter would hide at least something.</summary>
    public bool IsActive =>
        MinimumRiskLevel != RiskLevel.Informational ||
        Categories.Count > 0 ||
        !string.IsNullOrWhiteSpace(SearchText) ||
        OnlyMissingFiles ||
        OnlyUntrusted;

    /// <summary>Tests one entry against the filter.</summary>
    public bool Matches(ScanEntryViewModel entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (entry.RiskLevel < MinimumRiskLevel)
        {
            return false;
        }

        if (Categories.Count > 0 && !Categories.Contains(entry.Category))
        {
            return false;
        }

        if (OnlyMissingFiles && !entry.IsFileMissing)
        {
            return false;
        }

        if (OnlyUntrusted && IsTrusted(entry))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(SearchText))
        {
            return true;
        }

        // Every whitespace-separated term must match somewhere. Typing
        // "temp powershell" should narrow, not widen.
        foreach (var term in SearchText.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!entry.SearchIndex.Contains(term.ToLowerInvariant(), StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Applies the filter to a sequence, preserving its order.</summary>
    public IEnumerable<ScanEntryViewModel> Apply(IEnumerable<ScanEntryViewModel> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return entries.Where(Matches);
    }

    /// <summary>
    /// An entry counts as trusted only with a valid embedded or catalog
    /// signature. "Not checked" is not trust; it is absence of information, and
    /// treating it as trust would hide exactly what the filter is for.
    /// </summary>
    private static bool IsTrusted(ScanEntryViewModel entry) =>
        entry.Entry.SignatureStatus is SignatureStatus.Valid or SignatureStatus.ValidCatalog;
}
