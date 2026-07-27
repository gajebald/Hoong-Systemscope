using HoongSystemScope.Analysis.Rules;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis.Tests;

public sealed class LocationRuleTests
{
    private static readonly RiskEvaluationContext Context = RiskEvaluationContext.Default;

    [Theory]
    [InlineData(@"C:\$Recycle.Bin\S-1-5-21\x.exe", "RISK_LOCATION_RECYCLE_BIN")]
    [InlineData(@"C:\Users\bob\AppData\Local\Temp\x.exe", "RISK_LOCATION_TEMP")]
    [InlineData(@"C:\Users\bob\Downloads\x.exe", "RISK_LOCATION_DOWNLOADS")]
    [InlineData(@"C:\x.exe", "RISK_LOCATION_DRIVE_ROOT")]
    [InlineData(@"\\server\share\x.exe", "RISK_LOCATION_NETWORK")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Vendor\x.exe", "RISK_LOCATION_APPDATA")]
    public void Unusual_locations_are_reported_with_their_specific_code(string path, string expectedCode)
    {
        var reason = new SuspiciousLocationRule().Evaluate(EntryBuilder.Create(executablePath: path), Context);

        Assert.NotNull(reason);
        Assert.Equal(expectedCode, reason.Code);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Vendor\app.exe")]
    [InlineData(@"C:\Windows\System32\svchost.exe")]
    public void Ordinary_install_locations_are_not_reported(string path) =>
        Assert.Null(new SuspiciousLocationRule().Evaluate(EntryBuilder.Create(executablePath: path), Context));

    [Fact]
    public void A_temp_path_inside_appdata_is_only_scored_once()
    {
        // The rule returns a single reason, so overlapping classifications
        // cannot stack into an inflated score.
        var reason = new SuspiciousLocationRule().Evaluate(
            EntryBuilder.Create(executablePath: @"C:\Users\bob\AppData\Local\Temp\x.exe"),
            Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_LOCATION_TEMP", reason.Code);
    }

    [Fact]
    public void A_system_service_in_a_user_writable_directory_is_a_privilege_escalation_path()
    {
        var context = new RiskEvaluationContext(
            @"C:\Windows",
            directory => directory.Equals(@"C:\VendorTools", StringComparison.OrdinalIgnoreCase));

        var reason = new WritableDirectoryRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.Service,
                executablePath: @"C:\VendorTools\svc.exe",
                userName: "LocalSystem"),
            context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_WRITABLE_DIRECTORY", reason.Code);
        Assert.True(reason.ScoreDelta >= RiskThresholds.Default.Medium);
    }

    [Fact]
    public void A_user_program_in_a_user_writable_directory_is_not_escalation()
    {
        // A program the user could already replace, running as that same user,
        // grants nothing new.
        var context = new RiskEvaluationContext(@"C:\Windows", _ => true);

        var reason = new WritableDirectoryRule().Evaluate(
            EntryBuilder.Create(category: ScanCategory.RegistryRun, userName: @"MACHINE\bob"),
            context);

        Assert.Null(reason);
    }

    [Fact]
    public void An_unquoted_service_path_is_reported()
    {
        var reason = new UnquotedServicePathRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.Service,
                commandLine: @"C:\Program Files\Vendor\app.exe -run",
                metadata: EntryBuilder.Metadata((MetadataKeys.UnquotedPath, "true"))),
            Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_UNQUOTED_SERVICE_PATH", reason.Code);
    }

    [Fact]
    public void An_unquoted_run_key_value_is_not_a_service_path_finding()
    {
        // The hijack depends on the service control manager's resolution
        // behaviour, so the rule stays scoped to services and drivers.
        var reason = new UnquotedServicePathRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.RegistryRun,
                metadata: EntryBuilder.Metadata((MetadataKeys.UnquotedPath, "true"))),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void A_right_to_left_override_scores_highest_among_naming_tricks()
    {
        var bidi = new DeceptiveNameRule().Evaluate(
            EntryBuilder.Create(name: "invoice\u202Egnp.exe"), Context);
        var doubleExtension = new DeceptiveNameRule().Evaluate(
            EntryBuilder.Create(executablePath: @"C:\Temp\invoice.pdf.exe"), Context);

        Assert.NotNull(bidi);
        Assert.NotNull(doubleExtension);
        Assert.Equal("RISK_BIDI_OVERRIDE", bidi.Code);
        Assert.Equal("RISK_DOUBLE_EXTENSION", doubleExtension.Code);
        Assert.True(bidi.ScoreDelta > doubleExtension.ScoreDelta);
    }

    [Fact]
    public void An_ordinary_name_is_not_reported() =>
        Assert.Null(new DeceptiveNameRule().Evaluate(EntryBuilder.Create(name: "Vendor Updater"), Context));
}
