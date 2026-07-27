using System.Globalization;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis;

/// <summary>
/// Compares two scans of the same machine.
/// </summary>
/// <remarks>
/// <para>
/// Matching is done on <see cref="ScanEntry.Id"/>, which is derived from
/// category, location and name and never from the file behind them. That is
/// what lets the comparison distinguish "this autostart entry now points at a
/// different binary" from "one entry disappeared and an unrelated one
/// appeared". The first is the interesting case and the second is noise.
/// </para>
/// <para>
/// Only fields that describe what the entry <em>does</em> are compared. Risk
/// scores are excluded on purpose: changing a rule's weight must not make every
/// entry on the machine look modified.
/// </para>
/// </remarks>
public sealed class BaselineComparer
{
    /// <summary>Fields whose change is reported.</summary>
    private static readonly (string Name, Func<ScanEntry, string?> Read)[] TrackedFields =
    [
        ("CommandLine", e => e.CommandLine),
        ("ExecutablePath", e => e.ExecutablePath),
        ("Arguments", e => e.Arguments),
        ("Sha256", e => e.Sha256),
        ("SignatureStatus", e => e.SignatureStatus.ToString()),
        ("Publisher", e => e.Publisher),
        ("FileVersion", e => e.FileVersion),
        ("UserName", e => e.UserName),
        ("IsEnabled", e => e.IsEnabled?.ToString(CultureInfo.InvariantCulture)),
        ("FileExists", e => e.FileExists?.ToString(CultureInfo.InvariantCulture)),
    ];

    /// <summary>Compares an older scan against a newer one.</summary>
    /// <param name="baseline">The earlier scan.</param>
    /// <param name="current">The later scan.</param>
#pragma warning disable CA1822 // Kept as an instance method so the comparer stays injectable and can gain configuration later.
    public BaselineDiff Compare(ScanResult baseline, ScanResult current)
#pragma warning restore CA1822
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);

        var before = Index(baseline.Entries);
        var after = Index(current.Entries);

        var added = new List<BaselineEntryChange>();
        var removed = new List<BaselineEntryChange>();
        var modified = new List<BaselineEntryChange>();
        var unchanged = 0;

        foreach (var (id, entry) in after)
        {
            if (!before.TryGetValue(id, out var previous))
            {
                added.Add(new BaselineEntryChange
                {
                    Id = id,
                    Kind = BaselineChangeKind.Added,
                    After = entry,
                });
                continue;
            }

            var changes = Diff(previous, entry);

            if (changes.Count == 0)
            {
                unchanged++;
                continue;
            }

            modified.Add(new BaselineEntryChange
            {
                Id = id,
                Kind = BaselineChangeKind.Modified,
                Before = previous,
                After = entry,
                Changes = changes,
            });
        }

        foreach (var (id, entry) in before)
        {
            if (!after.ContainsKey(id))
            {
                removed.Add(new BaselineEntryChange
                {
                    Id = id,
                    Kind = BaselineChangeKind.Removed,
                    Before = entry,
                });
            }
        }

        return new BaselineDiff
        {
            BaselineTakenAtUtc = baseline.StartedAtUtc,
            CurrentTakenAtUtc = current.StartedAtUtc,
            Added = Sort(added),
            Removed = Sort(removed),
            Modified = Sort(modified),
            UnchangedCount = unchanged,
        };
    }

    private static List<FieldChange> Diff(ScanEntry before, ScanEntry after)
    {
        var changes = new List<FieldChange>();

        foreach (var (name, read) in TrackedFields)
        {
            var oldValue = read(before);
            var newValue = read(after);

            if (!string.Equals(oldValue, newValue, StringComparison.Ordinal))
            {
                changes.Add(new FieldChange { Field = name, OldValue = oldValue, NewValue = newValue });
            }
        }

        return changes;
    }

    /// <summary>
    /// Indexes by identity. A duplicate identity would mean two collectors
    /// claimed the same coordinates; the first wins so the comparison stays
    /// deterministic rather than throwing on a real machine.
    /// </summary>
    private static Dictionary<string, ScanEntry> Index(IReadOnlyList<ScanEntry> entries)
    {
        var index = new Dictionary<string, ScanEntry>(entries.Count, StringComparer.Ordinal);

        foreach (var entry in entries)
        {
            index.TryAdd(entry.Id, entry);
        }

        return index;
    }

    /// <summary>Orders changes so two runs over the same data produce identical output.</summary>
    private static BaselineEntryChange[] Sort(List<BaselineEntryChange> changes) =>
        changes
            .OrderByDescending(c => (c.After ?? c.Before)?.RiskLevel ?? RiskLevel.Informational)
            .ThenBy(c => (c.After ?? c.Before)?.Category ?? ScanCategory.Other)
            .ThenBy(c => (c.After ?? c.Before)?.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Id, StringComparer.Ordinal)
            .ToArray();
}
