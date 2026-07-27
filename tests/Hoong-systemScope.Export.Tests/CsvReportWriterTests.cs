using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export.Tests;

public sealed class CsvReportWriterTests
{
    [Theory]
    [InlineData("=cmd|'/c calc'!A1", "\"'=cmd|'/c calc'!A1\"")]
    [InlineData("+1+1", "\"'+1+1\"")]
    [InlineData("-2+3", "\"'-2+3\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    public void A_field_a_spreadsheet_would_evaluate_is_neutralised(string input, string expected)
    {
        // Command lines come from a possibly compromised machine. The report
        // must not become the payload when someone opens it in Excel.
        Assert.Equal(expected, CsvReportWriter.Escape(input));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Vendor\app.exe", "\"C:\\Program Files\\Vendor\\app.exe\"")]
    [InlineData("plain", "\"plain\"")]
    [InlineData(null, "\"\"")]
    [InlineData("", "\"\"")]
    public void Ordinary_fields_are_only_quoted(string? input, string expected) =>
        Assert.Equal(expected, CsvReportWriter.Escape(input));

    [Fact]
    public void Embedded_quotes_are_doubled()
    {
        Assert.Equal("\"say \"\"hello\"\"\"", CsvReportWriter.Escape("say \"hello\""));
    }

    [Fact]
    public void A_field_containing_a_comma_stays_one_cell()
    {
        var csv = new CsvReportWriter().Write(SampleScan.Create(
            SampleScan.Entry(name: "Vendor, Inc. updater")));

        var dataLine = csv.Split('\n')[1];

        Assert.Contains("\"Vendor, Inc. updater\"", dataLine, StringComparison.Ordinal);
    }

    [Fact]
    public void The_header_row_matches_the_field_count_of_every_data_row()
    {
        var csv = new CsvReportWriter().Write(SampleScan.Create(
            SampleScan.Entry(name: "One"),
            SampleScan.Entry(name: "Two", category: ScanCategory.Service)));

        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var headerFields = CountFields(lines[0]);

        Assert.Equal(3, lines.Length);
        Assert.All(lines, line => Assert.Equal(headerFields, CountFields(line)));
    }

    [Fact]
    public void Entries_are_listed_with_the_highest_risk_first()
    {
        var csv = new CsvReportWriter().Write(SampleScan.Create(
            SampleScan.Entry(name: "Quiet", riskLevel: RiskLevel.Informational, riskScore: 0),
            SampleScan.Entry(name: "Loud", riskLevel: RiskLevel.High, riskScore: 50),
            SampleScan.Entry(name: "Middle", riskLevel: RiskLevel.Medium, riskScore: 30)));

        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.Contains("Loud", lines[1], StringComparison.Ordinal);
        Assert.Contains("Middle", lines[2], StringComparison.Ordinal);
        Assert.Contains("Quiet", lines[3], StringComparison.Ordinal);
    }

    /// <summary>Counts top-level fields, honouring quoting.</summary>
    private static int CountFields(string line)
    {
        var fields = 1;
        var inQuotes = false;

        for (var index = 0; index < line.Length; index++)
        {
            if (line[index] == '"')
            {
                if (inQuotes && index + 1 < line.Length && line[index + 1] == '"')
                {
                    index++;
                    continue;
                }

                inQuotes = !inQuotes;
            }
            else if (line[index] == ',' && !inQuotes)
            {
                fields++;
            }
        }

        return fields;
    }
}
