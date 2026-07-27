using HoongSystemScope.Core.Models;
using HoongSystemScope.ViewModels;

namespace HoongSystemScope.ViewModels.Tests;

public sealed class EntryFilterTests
{
    private static ScanEntryViewModel Row(
        string name = "Updater",
        ScanCategory category = ScanCategory.RegistryRun,
        string? path = @"C:\Program Files\Vendor\updater.exe",
        string? publisher = "Vendor GmbH",
        bool? fileExists = true,
        SignatureStatus signature = SignatureStatus.Valid,
        RiskLevel risk = RiskLevel.Informational) =>
        new(ScanBuilder.Entry(
            name: name,
            category: category,
            executablePath: path,
            publisher: publisher,
            fileExists: fileExists,
            signatureStatus: signature,
            riskLevel: risk));

    [Fact]
    public void The_empty_filter_hides_nothing()
    {
        Assert.False(EntryFilter.None.IsActive);
        Assert.True(EntryFilter.None.Matches(Row()));
    }

    [Fact]
    public void The_minimum_risk_level_hides_quieter_entries()
    {
        var filter = new EntryFilter { MinimumRiskLevel = RiskLevel.Medium };

        Assert.True(filter.IsActive);
        Assert.False(filter.Matches(Row(risk: RiskLevel.Low)));
        Assert.True(filter.Matches(Row(risk: RiskLevel.Medium)));
        Assert.True(filter.Matches(Row(risk: RiskLevel.Critical)));
    }

    [Fact]
    public void An_empty_category_set_means_every_category()
    {
        var filter = new EntryFilter();

        Assert.True(filter.Matches(Row(category: ScanCategory.Service)));
        Assert.True(filter.Matches(Row(category: ScanCategory.HostsFile)));
    }

    [Fact]
    public void Selecting_categories_hides_the_others()
    {
        var filter = new EntryFilter
        {
            Categories = new HashSet<ScanCategory> { ScanCategory.Service, ScanCategory.Driver },
        };

        Assert.True(filter.Matches(Row(category: ScanCategory.Service)));
        Assert.False(filter.Matches(Row(category: ScanCategory.RegistryRun)));
    }

    [Fact]
    public void Search_looks_across_name_path_and_publisher()
    {
        Assert.True(new EntryFilter { SearchText = "updater" }.Matches(Row()));
        Assert.True(new EntryFilter { SearchText = "program files" }.Matches(Row()));
        Assert.True(new EntryFilter { SearchText = "vendor gmbh" }.Matches(Row()));
        Assert.False(new EntryFilter { SearchText = "nothing here" }.Matches(Row()));
    }

    [Fact]
    public void Search_is_case_insensitive()
    {
        Assert.True(new EntryFilter { SearchText = "UPDATER" }.Matches(Row()));
    }

    [Fact]
    public void Several_search_terms_narrow_rather_than_widen()
    {
        // Typing a second word should refine the result, not add to it.
        var row = Row(name: "Updater", path: @"C:\Temp\updater.exe");

        Assert.True(new EntryFilter { SearchText = "updater temp" }.Matches(row));
        Assert.False(new EntryFilter { SearchText = "updater system32" }.Matches(row));
    }

    [Fact]
    public void The_missing_file_filter_keeps_only_broken_entries()
    {
        var filter = new EntryFilter { OnlyMissingFiles = true };

        Assert.True(filter.Matches(Row(fileExists: false)));
        Assert.False(filter.Matches(Row(fileExists: true)));
    }

    [Theory]
    [InlineData(SignatureStatus.Valid, false)]
    [InlineData(SignatureStatus.ValidCatalog, false)]
    [InlineData(SignatureStatus.Unsigned, true)]
    [InlineData(SignatureStatus.Invalid, true)]
    [InlineData(SignatureStatus.NotChecked, true)]
    public void The_untrusted_filter_treats_unchecked_as_untrusted(SignatureStatus status, bool expectedVisible)
    {
        // "Not checked" is absence of information, not trust. Counting it as
        // trusted would hide exactly what this filter exists to surface.
        var filter = new EntryFilter { OnlyUntrusted = true };

        Assert.Equal(expectedVisible, filter.Matches(Row(signature: status)));
    }

    [Fact]
    public void Filters_combine_conjunctively()
    {
        var filter = new EntryFilter
        {
            MinimumRiskLevel = RiskLevel.Medium,
            OnlyMissingFiles = true,
        };

        Assert.False(filter.Matches(Row(risk: RiskLevel.High, fileExists: true)));
        Assert.False(filter.Matches(Row(risk: RiskLevel.Low, fileExists: false)));
        Assert.True(filter.Matches(Row(risk: RiskLevel.High, fileExists: false)));
    }

    [Fact]
    public void Apply_preserves_the_incoming_order()
    {
        var rows = new[] { Row(name: "Charlie"), Row(name: "Alpha"), Row(name: "Bravo") };

        var filtered = new EntryFilter().Apply(rows).Select(r => r.Name).ToArray();

        Assert.Equal(["Charlie", "Alpha", "Bravo"], filtered);
    }

    [Fact]
    public void An_entry_without_a_path_still_matches_on_its_name()
    {
        var row = Row(name: "example.com", category: ScanCategory.HostsFile, path: null, publisher: null);

        Assert.True(new EntryFilter { SearchText = "example" }.Matches(row));
    }
}
