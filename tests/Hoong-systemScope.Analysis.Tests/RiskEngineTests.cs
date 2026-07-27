using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis.Tests;

public sealed class RiskEngineTests
{
    private static readonly RiskEvaluationContext Context = RiskEvaluationContext.Default;

    [Fact]
    public void An_ordinary_signed_application_stays_informational()
    {
        // The most important property of the whole engine: a normal machine
        // must come back mostly green, or nobody will read the report.
        var entry = RiskEngine.CreateDefault().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Program Files\Vendor\app.exe",
                signature: new SignatureInfo { Status = SignatureStatus.Valid, SubjectName = "Vendor GmbH" }),
            Context);

        Assert.Equal(RiskLevel.Informational, entry.RiskLevel);
        Assert.Equal(0, entry.RiskScore);
        Assert.Empty(entry.RiskReasons);
    }

    [Fact]
    public void A_microsoft_system_binary_stays_informational()
    {
        var entry = RiskEngine.CreateDefault().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Windows\System32\SecurityHealthSystray.exe",
                signature: EntryBuilder.MicrosoftSignature),
            Context);

        Assert.Equal(RiskLevel.Informational, entry.RiskLevel);
    }

    [Fact]
    public void Independent_indicators_accumulate_into_a_high_verdict()
    {
        var entry = RiskEngine.CreateDefault().Evaluate(
            EntryBuilder.Create(
                name: "Updater",
                executablePath: @"C:\Users\bob\AppData\Local\Temp\svchost.exe",
                commandLine: @"C:\Users\bob\AppData\Local\Temp\svchost.exe",
                signatureStatus: SignatureStatus.Unsigned),
            Context);

        // Unsigned plus running from a temporary directory.
        Assert.True(entry.RiskLevel >= RiskLevel.Medium);
        Assert.Contains(entry.RiskReasons, r => r.Code == "RISK_UNSIGNED");
        Assert.Contains(entry.RiskReasons, r => r.Code == "RISK_LOCATION_TEMP");
    }

    [Fact]
    public void Every_point_of_the_score_belongs_to_a_named_reason()
    {
        // This is the property the whole design exists for: the number must be
        // reconstructible from the explanation.
        var entry = RiskEngine.CreateDefault().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Users\bob\AppData\Local\Temp\payload.exe",
                commandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
                signatureStatus: SignatureStatus.Unsigned),
            Context);

        Assert.Equal(entry.RiskReasons.Sum(r => r.ScoreDelta), entry.RiskScore);
        Assert.All(entry.RiskReasons, r => Assert.False(string.IsNullOrWhiteSpace(r.RuleId)));
        Assert.All(entry.RiskReasons, r => Assert.False(string.IsNullOrWhiteSpace(r.Title)));
    }

    [Fact]
    public void Reasons_are_ordered_by_weight_so_the_report_leads_with_what_matters()
    {
        var entry = RiskEngine.CreateDefault().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Users\bob\AppData\Local\Temp\payload.exe",
                commandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
                signatureStatus: SignatureStatus.Unsigned),
            Context);

        var deltas = entry.RiskReasons.Select(r => r.ScoreDelta).ToArray();
        Assert.Equal(deltas.OrderByDescending(d => d), deltas);
    }

    [Fact]
    public void The_score_never_goes_below_zero()
    {
        // A mitigating rule may outweigh everything else. The scale must stay
        // meaningful without discarding the explanation.
        var entry = RiskEngine.CreateDefault().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Windows\System32\svchost.exe",
                signature: EntryBuilder.MicrosoftSignature),
            Context);

        Assert.Equal(0, entry.RiskScore);
        Assert.Contains(entry.RiskReasons, r => r.ScoreDelta < 0);
    }

    [Theory]
    [InlineData(0, RiskLevel.Informational)]
    [InlineData(9, RiskLevel.Informational)]
    [InlineData(10, RiskLevel.Low)]
    [InlineData(24, RiskLevel.Low)]
    [InlineData(25, RiskLevel.Medium)]
    [InlineData(44, RiskLevel.Medium)]
    [InlineData(45, RiskLevel.High)]
    [InlineData(69, RiskLevel.High)]
    [InlineData(70, RiskLevel.Critical)]
    [InlineData(500, RiskLevel.Critical)]
    public void Scores_map_onto_the_documented_thresholds(int score, RiskLevel expected) =>
        Assert.Equal(expected, RiskThresholds.Default.Classify(score));

    [Fact]
    public void Scoring_a_result_refreshes_its_summary()
    {
        var result = new ScanResult
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
            StartedAtUtc = DateTimeOffset.UnixEpoch,
            CompletedAtUtc = DateTimeOffset.UnixEpoch,
            Entries =
            [
                EntryBuilder.Create(name: "Clean", signature: EntryBuilder.MicrosoftSignature,
                    executablePath: @"C:\Windows\System32\a.exe"),
                EntryBuilder.Create(name: "Dirty", executablePath: @"C:\Users\b\AppData\Local\Temp\x.exe",
                    signatureStatus: SignatureStatus.Unsigned),
                EntryBuilder.Create(name: "Gone", fileExists: false, executablePath: @"C:\gone.exe"),
            ],
        };

        var scored = RiskEngine.CreateDefault().Evaluate(result, Context);

        Assert.NotNull(scored.Summary);
        Assert.Equal(3, scored.Summary.TotalEntries);
        Assert.Equal(1, scored.Summary.MissingFileCount);
        Assert.True(scored.Summary.HighestRiskLevel >= RiskLevel.Medium);
        Assert.Equal(3, scored.Summary.ByCategory[ScanCategory.RegistryRun]);
    }

    [Fact]
    public void Every_built_in_rule_has_a_distinct_identifier()
    {
        var ruleIds = RiskRules.CreateDefaultSet().Select(r => r.RuleId).ToArray();

        Assert.Equal(ruleIds.Length, ruleIds.Distinct(StringComparer.Ordinal).Count());
    }
}
