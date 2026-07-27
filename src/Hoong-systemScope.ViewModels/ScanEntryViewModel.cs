using System.Globalization;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.ViewModels;

/// <summary>
/// One row of the findings grid.
/// </summary>
/// <remarks>
/// A thin projection over <see cref="ScanEntry"/> that pre-formats what the
/// view binds to. Doing the formatting here rather than in XAML converters
/// keeps it testable, and keeps the same wording available to a future front
/// end that is not WPF.
/// </remarks>
public sealed class ScanEntryViewModel
{
    /// <summary>Wraps a scan entry.</summary>
    public ScanEntryViewModel(ScanEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        Entry = entry;
        SearchIndex = BuildSearchIndex(entry);
    }

    /// <summary>The underlying entry.</summary>
    public ScanEntry Entry { get; }

    /// <summary>Stable identity.</summary>
    public string Id => Entry.Id;

    /// <summary>Risk bucket.</summary>
    public RiskLevel RiskLevel => Entry.RiskLevel;

    /// <summary>Accumulated score.</summary>
    public int RiskScore => Entry.RiskScore;

    /// <summary>Category of the entry.</summary>
    public ScanCategory Category => Entry.Category;

    /// <summary>Name of the entry.</summary>
    public string Name => Entry.Name;

    /// <summary>Where it was found.</summary>
    public string Location => Entry.Location;

    /// <summary>Resolved executable, or a placeholder.</summary>
    public string FilePath => Entry.ExecutablePath ?? "—";

    /// <summary>Publisher, or a placeholder.</summary>
    public string Publisher => Entry.Publisher ?? "—";

    /// <summary>Account the entry runs as, or a placeholder.</summary>
    public string UserName => Entry.UserName ?? "—";

    /// <summary>SHA-256 of the target, or a placeholder.</summary>
    public string Sha256 => Entry.Sha256 ?? "—";

    /// <summary>Command line as recorded, or a placeholder.</summary>
    public string CommandLine => Entry.CommandLine ?? Entry.ExecutablePath ?? "—";

    /// <summary>True when the target file is known to be missing.</summary>
    public bool IsFileMissing => Entry.FileExists == false;

    /// <summary>Signature state in words, including the missing-file case.</summary>
    public string SignatureCaption => Entry.SignatureStatus switch
    {
        SignatureStatus.NotChecked => "not checked",
        SignatureStatus.Valid => "signed",
        SignatureStatus.ValidCatalog => "signed (catalog)",
        SignatureStatus.Unsigned => "unsigned",
        SignatureStatus.Invalid => "signature broken",
        SignatureStatus.Expired => "signature expired",
        SignatureStatus.UntrustedRoot => "untrusted root",
        SignatureStatus.Revoked => "certificate revoked",
        SignatureStatus.FileNotFound => "file missing",
        _ => "verification error",
    };

    /// <summary>Risk level and score together, for a compact column.</summary>
    public string RiskCaption => string.Create(
        CultureInfo.InvariantCulture,
        $"{Entry.RiskLevel} ({Entry.RiskScore})");

    /// <summary>The reasons behind the score, ready to list in the detail pane.</summary>
    public IReadOnlyList<RiskReason> Reasons => Entry.RiskReasons;

    /// <summary>True when there is anything to explain.</summary>
    public bool HasReasons => Entry.RiskReasons.Count > 0;

    /// <summary>
    /// Everything the free-text filter searches, lower-cased once at
    /// construction. Filtering runs on every keystroke over potentially several
    /// thousand rows, so it must not rebuild this each time.
    /// </summary>
    internal string SearchIndex { get; }

    private static string BuildSearchIndex(ScanEntry entry)
    {
        var parts = new[]
        {
            entry.Name,
            entry.Location,
            entry.ExecutablePath,
            entry.Arguments,
            entry.CommandLine,
            entry.Publisher,
            entry.ProductName,
            entry.FileDescription,
            entry.UserName,
            entry.Sha256,
            entry.Category.ToString(),
        };

        return string.Join(
            ' ',
            parts.Where(p => !string.IsNullOrEmpty(p))).ToLowerInvariant();
    }
}
