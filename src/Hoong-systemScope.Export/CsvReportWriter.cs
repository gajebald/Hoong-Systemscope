using System.Globalization;
using System.Text;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export;

/// <summary>
/// Writes a flat, one-row-per-entry report for spreadsheets.
/// </summary>
/// <remarks>
/// Spreadsheet applications evaluate a cell that begins with <c>=</c>,
/// <c>+</c>, <c>-</c> or <c>@</c> as a formula, and command lines pulled out of
/// a possibly compromised machine are attacker-controlled text. A diagnostic
/// tool must not turn its own report into the payload, so those cells are
/// prefixed before they are quoted.
/// </remarks>
public sealed class CsvReportWriter : IReportWriter
{
    private static readonly string[] EntryHeader =
    [
        "Id", "Category", "Name", "Location", "RiskLevel", "RiskScore", "RiskReasons",
        "ExecutablePath", "Arguments", "CommandLine", "UserName", "IsEnabled", "FileExists",
        "Publisher", "ProductName", "FileVersion", "SignatureStatus", "SignatureSubject",
        "Sha256", "CollectedAtUtc",
    ];

    private static readonly string[] DiffHeader =
    [
        "Change", "Id", "Category", "Name", "Location", "RiskLevel", "RiskScore",
        "ChangedFields", "OldValues", "NewValues",
    ];

    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Csv;

    /// <inheritdoc />
    public string Write(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var builder = new StringBuilder();
        AppendRow(builder, EntryHeader);

        foreach (var entry in ReportOrder.Sort(result.Entries))
        {
            AppendRow(builder,
            [
                entry.Id,
                entry.Category.ToString(),
                entry.Name,
                entry.Location,
                entry.RiskLevel.ToString(),
                entry.RiskScore.ToString(CultureInfo.InvariantCulture),
                string.Join("; ", entry.RiskReasons.Select(r => r.Code)),
                entry.ExecutablePath,
                entry.Arguments,
                entry.CommandLine,
                entry.UserName,
                entry.IsEnabled?.ToString(CultureInfo.InvariantCulture),
                entry.FileExists?.ToString(CultureInfo.InvariantCulture),
                entry.Publisher,
                entry.ProductName,
                entry.FileVersion,
                entry.SignatureStatus.ToString(),
                entry.Signature?.SubjectName,
                entry.Sha256,
                entry.CollectedAtUtc.ToString("O", CultureInfo.InvariantCulture),
            ]);
        }

        return builder.ToString();
    }

    /// <inheritdoc />
    public string Write(BaselineDiff diff)
    {
        ArgumentNullException.ThrowIfNull(diff);

        var builder = new StringBuilder();
        AppendRow(builder, DiffHeader);

        foreach (var change in diff.Added.Concat(diff.Modified).Concat(diff.Removed))
        {
            var entry = change.After ?? change.Before;

            AppendRow(builder,
            [
                change.Kind.ToString(),
                change.Id,
                entry?.Category.ToString(),
                entry?.Name,
                entry?.Location,
                entry?.RiskLevel.ToString(),
                entry?.RiskScore.ToString(CultureInfo.InvariantCulture),
                string.Join("; ", change.Changes.Select(c => c.Field)),
                string.Join("; ", change.Changes.Select(c => c.OldValue ?? string.Empty)),
                string.Join("; ", change.Changes.Select(c => c.NewValue ?? string.Empty)),
            ]);
        }

        return builder.ToString();
    }

    private static void AppendRow(StringBuilder builder, IReadOnlyList<string?> fields)
    {
        for (var index = 0; index < fields.Count; index++)
        {
            if (index > 0)
            {
                builder.Append(',');
            }

            builder.Append(Escape(fields[index]));
        }

        builder.Append('\n');
    }

    /// <summary>
    /// Quotes a field and neutralises anything a spreadsheet would treat as a
    /// formula.
    /// </summary>
    internal static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        var text = value;

        // A leading =, +, - or @ makes the cell a formula. Prefixing with an
        // apostrophe keeps the text readable and inert.
        if (text[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            text = "'" + text;
        }

        return "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}

/// <summary>Shared ordering so every format lists entries the same way.</summary>
internal static class ReportOrder
{
    /// <summary>
    /// Highest risk first, then grouped by category and name. Deterministic, so
    /// two reports of an unchanged machine diff cleanly.
    /// </summary>
    public static IEnumerable<ScanEntry> Sort(IEnumerable<ScanEntry> entries) =>
        entries
            .OrderByDescending(e => e.RiskLevel)
            .ThenByDescending(e => e.RiskScore)
            .ThenBy(e => e.Category)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Id, StringComparer.Ordinal);
}
