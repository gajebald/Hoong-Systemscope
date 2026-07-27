using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis.Tests;

public sealed class BaselineComparerTests
{
    private static ScanResult Scan(DateTimeOffset takenAt, params ScanEntry[] entries) => new()
    {
        SchemaVersion = ScanResult.CurrentSchemaVersion,
        ToolVersion = "test",
        Machine = new MachineInfo
        {
            MachineName = "M",
            OperatingSystem = "Windows",
            Architecture = "X64",
            UserName = "u",
            IsElevated = false,
        },
        StartedAtUtc = takenAt,
        CompletedAtUtc = takenAt,
        Entries = entries,
    };

    private static readonly DateTimeOffset Before = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset After = new(2026, 2, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void An_identical_pair_of_scans_produces_an_empty_diff()
    {
        var entry = EntryBuilder.Create(name: "Updater", sha256: "aaa");

        var diff = new BaselineComparer().Compare(Scan(Before, entry), Scan(After, entry));

        Assert.True(diff.IsEmpty);
        Assert.Equal(1, diff.UnchangedCount);
    }

    [Fact]
    public void A_new_entry_is_reported_as_added()
    {
        var diff = new BaselineComparer().Compare(
            Scan(Before),
            Scan(After, EntryBuilder.Create(name: "Newcomer")));

        var added = Assert.Single(diff.Added);
        Assert.Equal(BaselineChangeKind.Added, added.Kind);
        Assert.Equal("Newcomer", added.After?.Name);
        Assert.Null(added.Before);
    }

    [Fact]
    public void A_disappeared_entry_is_reported_as_removed()
    {
        var diff = new BaselineComparer().Compare(
            Scan(Before, EntryBuilder.Create(name: "Departed")),
            Scan(After));

        var removed = Assert.Single(diff.Removed);
        Assert.Equal(BaselineChangeKind.Removed, removed.Kind);
        Assert.Equal("Departed", removed.Before?.Name);
    }

    [Fact]
    public void A_swapped_binary_is_a_modification_rather_than_a_removal_plus_an_addition()
    {
        // The whole point of a stable identity: the autostart entry is the
        // same, the file behind it is not. Reporting that as two unrelated
        // events would bury the finding.
        var diff = new BaselineComparer().Compare(
            Scan(Before, EntryBuilder.Create(name: "Updater", sha256: "old")),
            Scan(After, EntryBuilder.Create(name: "Updater", sha256: "new")));

        Assert.Empty(diff.Added);
        Assert.Empty(diff.Removed);

        var modified = Assert.Single(diff.Modified);
        var change = Assert.Single(modified.Changes);
        Assert.Equal("Sha256", change.Field);
        Assert.Equal("old", change.OldValue);
        Assert.Equal("new", change.NewValue);
    }

    [Fact]
    public void Several_changed_fields_are_listed_individually()
    {
        var diff = new BaselineComparer().Compare(
            Scan(Before, EntryBuilder.Create(
                name: "Updater",
                executablePath: @"C:\Program Files\Vendor\app.exe",
                sha256: "old",
                signatureStatus: SignatureStatus.Valid)),
            Scan(After, EntryBuilder.Create(
                name: "Updater",
                executablePath: @"C:\Users\bob\AppData\Local\Temp\app.exe",
                sha256: "new",
                signatureStatus: SignatureStatus.Unsigned)));

        var modified = Assert.Single(diff.Modified);
        var fields = modified.Changes.Select(c => c.Field).ToArray();

        Assert.Contains("ExecutablePath", fields);
        Assert.Contains("Sha256", fields);
        Assert.Contains("SignatureStatus", fields);
    }

    [Fact]
    public void A_changed_risk_score_alone_is_not_a_modification()
    {
        // Adjusting a rule's weight must not make every entry on the machine
        // look like it changed.
        var before = EntryBuilder.Create(name: "Updater", sha256: "same") with
        {
            RiskScore = 10,
            RiskLevel = RiskLevel.Low,
        };
        var after = EntryBuilder.Create(name: "Updater", sha256: "same") with
        {
            RiskScore = 60,
            RiskLevel = RiskLevel.High,
        };

        var diff = new BaselineComparer().Compare(Scan(Before, before), Scan(After, after));

        Assert.True(diff.IsEmpty);
    }

    [Fact]
    public void The_diff_does_not_depend_on_the_order_entries_arrive_in()
    {
        var a = EntryBuilder.Create(name: "Alpha");
        var b = EntryBuilder.Create(name: "Bravo");
        var c = EntryBuilder.Create(name: "Charlie");

        var first = new BaselineComparer().Compare(Scan(Before, a), Scan(After, a, b, c));
        var second = new BaselineComparer().Compare(Scan(Before, a), Scan(After, c, b, a));

        Assert.Equal(
            first.Added.Select(x => x.Id),
            second.Added.Select(x => x.Id));
    }

    [Fact]
    public void The_diff_records_when_each_scan_was_taken()
    {
        var diff = new BaselineComparer().Compare(Scan(Before), Scan(After));

        Assert.Equal(Before, diff.BaselineTakenAtUtc);
        Assert.Equal(After, diff.CurrentTakenAtUtc);
    }
}
