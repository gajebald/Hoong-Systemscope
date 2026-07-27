using System.Text.Json;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export.Tests;

public sealed class JsonRoundTripTests
{
    [Fact]
    public void A_scan_survives_a_round_trip_unchanged()
    {
        // JSON is both the report and the baseline format, so any field that
        // does not round-trip would silently corrupt a comparison.
        var original = SampleScan.Create(
            SampleScan.Entry(
                name: "Updater",
                sha256: "9f2b1c",
                signatureStatus: SignatureStatus.Valid,
                riskLevel: RiskLevel.Medium,
                riskScore: 30,
                reasons:
                [
                    new RiskReason
                    {
                        RuleId = "SuspiciousLocation",
                        Code = "RISK_LOCATION_TEMP",
                        Title = "Runs from a temporary directory.",
                        Detail = @"C:\Temp\x.exe",
                        ScoreDelta = 25,
                    },
                ]),
            SampleScan.Entry(category: ScanCategory.Service, name: "Spooler", fileExists: false));

        var json = ScanJson.Serialize(original);
        var restored = ScanJson.Deserialize(json);

        // Records compare their collection members by reference, so equality on
        // the objects proves nothing here. Re-serialising does: if any field
        // failed to round-trip, the second document differs from the first.
        Assert.Equal(json, ScanJson.Serialize(restored));

        // Spot-check the members that carry the most structure.
        Assert.Equal(2, restored.Entries.Count);
        Assert.Equal("9f2b1c", restored.Entries[0].Sha256);
        Assert.Equal("RISK_LOCATION_TEMP", Assert.Single(restored.Entries[0].RiskReasons).Code);
        Assert.Equal("yes", restored.Entries[0].Metadata["sample"]);
        Assert.False(restored.Entries[1].FileExists);
        Assert.Equal(SignatureStatus.Valid, restored.Entries[0].Signature?.Status);
        Assert.Equal(original.Machine, restored.Machine);
        Assert.Equal(original.StartedAtUtc, restored.StartedAtUtc);
    }

    [Fact]
    public void Enums_are_written_as_names_rather_than_numbers()
    {
        // A numeric enum would be unreadable and would change meaning if a
        // value were ever inserted in the middle of the enum.
        var json = ScanJson.Serialize(SampleScan.Create(
            SampleScan.Entry(category: ScanCategory.ScheduledTask, riskLevel: RiskLevel.High)));

        Assert.Contains("\"ScheduledTask\"", json, StringComparison.Ordinal);
        Assert.Contains("\"High\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void The_schema_version_is_recorded()
    {
        using var document = JsonDocument.Parse(ScanJson.Serialize(SampleScan.Create()));

        Assert.Equal(
            ScanResult.CurrentSchemaVersion,
            document.RootElement.GetProperty("schemaVersion").GetInt32());
    }

    [Fact]
    public void A_future_schema_version_is_refused_rather_than_misread()
    {
        var json = ScanJson.Serialize(SampleScan.Create() with { SchemaVersion = 99 });

        var exception = Assert.Throws<InvalidDataException>(() => ScanJson.Deserialize(json));

        Assert.Contains("99", exception.Message, StringComparison.Ordinal);
        Assert.Contains("newer Hoong-systemScope", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Malformed_input_produces_a_clear_error()
    {
        var exception = Assert.Throws<InvalidDataException>(() => ScanJson.Deserialize("{ not json"));

        Assert.Contains("not a valid Hoong-systemScope scan", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_baseline_diff_serializes()
    {
        var diff = new BaselineDiff
        {
            BaselineTakenAtUtc = SampleScan.StartedAt,
            CurrentTakenAtUtc = SampleScan.StartedAt.AddDays(1),
            Added = [new BaselineEntryChange { Id = "abc", Kind = BaselineChangeKind.Added, After = SampleScan.Entry() }],
        };

        var json = ScanJson.Serialize(diff);

        Assert.Contains("\"Added\"", json, StringComparison.Ordinal);
        Assert.Contains("\"added\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_baseline_can_be_saved_and_loaded_again()
    {
        var path = Path.Combine(Path.GetTempPath(), $"hoong-systemscope-{Guid.NewGuid():N}", "baseline.json");
        var original = SampleScan.Create();

        try
        {
            await BaselineStore.SaveAsync(original, path);
            var loaded = await BaselineStore.LoadAsync(path);

            Assert.Equal(ScanJson.Serialize(original), ScanJson.Serialize(loaded));
        }
        finally
        {
            var directory = Path.GetDirectoryName(path);
            if (directory is not null && Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Loading_a_missing_baseline_names_the_path()
    {
        var path = Path.Combine(Path.GetTempPath(), $"hoong-systemscope-missing-{Guid.NewGuid():N}.json");

        var exception = await Assert.ThrowsAsync<FileNotFoundException>(() => BaselineStore.LoadAsync(path));

        Assert.Contains(path, exception.Message, StringComparison.Ordinal);
    }
}
