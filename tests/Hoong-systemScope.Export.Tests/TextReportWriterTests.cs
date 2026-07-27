using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export.Tests;

public sealed class TextReportWriterTests
{
    [Fact]
    public void The_report_spells_out_why_an_entry_was_rated()
    {
        // A level without its justification invites the reader to act on a
        // number they do not understand. The reasons are the deliverable.
        var report = new TextReportWriter().Write(SampleScan.Create(SampleScan.Entry(
            name: "Suspicious",
            riskLevel: RiskLevel.High,
            riskScore: 47,
            reasons:
            [
                new RiskReason
                {
                    RuleId = "SuspiciousLocation",
                    Code = "RISK_LOCATION_TEMP",
                    Title = "The program runs from a temporary directory.",
                    Detail = @"C:\Temp\x.exe",
                    ScoreDelta = 25,
                },
                new RiskReason
                {
                    RuleId = "UnsignedBinary",
                    Code = "RISK_UNSIGNED",
                    Title = "The file carries no digital signature.",
                    ScoreDelta = 12,
                },
            ])));

        Assert.Contains("Why this was rated:", report, StringComparison.Ordinal);
        Assert.Contains("The program runs from a temporary directory.", report, StringComparison.Ordinal);
        Assert.Contains("The file carries no digital signature.", report, StringComparison.Ordinal);
        Assert.Contains("+25", report, StringComparison.Ordinal);
        Assert.Contains(@"C:\Temp\x.exe", report, StringComparison.Ordinal);
    }

    [Fact]
    public void Coverage_gaps_appear_before_the_findings()
    {
        // A reader who does not know the report is incomplete will read the
        // absence of a finding as evidence there is none.
        var result = SampleScan.Create() with
        {
            Errors =
            [
                new ScanError
                {
                    CollectorId = "services",
                    Severity = ScanErrorSeverity.Warning,
                    Message = "Access to 'HKLM\\SYSTEM' was denied. Run elevated to include it.",
                    Location = @"HKLM\SYSTEM",
                },
            ],
        };

        var report = new TextReportWriter().Write(result);

        var gapsIndex = report.IndexOf("Coverage gaps", StringComparison.Ordinal);
        var findingsIndex = report.IndexOf("Findings", StringComparison.Ordinal);

        Assert.True(gapsIndex >= 0);
        Assert.True(findingsIndex > gapsIndex);
        Assert.Contains("Run elevated", report, StringComparison.Ordinal);
    }

    [Fact]
    public void The_report_states_that_nothing_was_changed()
    {
        var report = new TextReportWriter().Write(SampleScan.Create());

        Assert.Contains("Nothing on this machine was modified", report, StringComparison.Ordinal);
        Assert.Contains("not an antivirus product", report, StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_file_is_called_out_next_to_the_path()
    {
        var report = new TextReportWriter().Write(SampleScan.Create(
            SampleScan.Entry(name: "Ghost", executablePath: @"C:\gone\ghost.exe", fileExists: false)));

        Assert.Contains(@"C:\gone\ghost.exe  (file does not exist)", report, StringComparison.Ordinal);
    }

    [Fact]
    public void Whether_the_scan_ran_elevated_is_stated_in_the_header()
    {
        var elevated = new TextReportWriter().Write(SampleScan.Create());
        var plain = new TextReportWriter().Write(SampleScan.Create() with
        {
            Machine = SampleScan.Create().Machine with { IsElevated = false },
        });

        Assert.Contains("(elevated)", elevated, StringComparison.Ordinal);
        Assert.Contains("(not elevated)", plain, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unchanged_comparison_says_so_plainly()
    {
        var report = new TextReportWriter().Write(new BaselineDiff
        {
            BaselineTakenAtUtc = SampleScan.StartedAt,
            CurrentTakenAtUtc = SampleScan.StartedAt.AddDays(1),
            UnchangedCount = 214,
        });

        Assert.Contains("No changes.", report, StringComparison.Ordinal);
        Assert.Contains("214", report, StringComparison.Ordinal);
    }

    [Fact]
    public void A_modified_entry_shows_the_before_and_after_of_each_field()
    {
        var report = new TextReportWriter().Write(new BaselineDiff
        {
            BaselineTakenAtUtc = SampleScan.StartedAt,
            CurrentTakenAtUtc = SampleScan.StartedAt.AddDays(1),
            Modified =
            [
                new BaselineEntryChange
                {
                    Id = "abc",
                    Kind = BaselineChangeKind.Modified,
                    Before = SampleScan.Entry(sha256: "old"),
                    After = SampleScan.Entry(sha256: "new"),
                    Changes = [new FieldChange { Field = "Sha256", OldValue = "old", NewValue = "new" }],
                },
            ],
        });

        Assert.Contains("Modified (1)", report, StringComparison.Ordinal);
        Assert.Contains("before: old", report, StringComparison.Ordinal);
        Assert.Contains("after : new", report, StringComparison.Ordinal);
    }

    [Fact]
    public void The_same_input_always_produces_the_same_report()
    {
        // Byte-for-byte stability is what lets two reports be diffed.
        var result = SampleScan.Create(
            SampleScan.Entry(name: "B", riskLevel: RiskLevel.Medium, riskScore: 30),
            SampleScan.Entry(name: "A", riskLevel: RiskLevel.Medium, riskScore: 30));

        Assert.Equal(new TextReportWriter().Write(result), new TextReportWriter().Write(result));
    }
}
