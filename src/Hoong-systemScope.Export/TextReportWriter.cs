using System.Globalization;
using System.Text;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export;

/// <summary>
/// Writes the report a person actually reads.
/// </summary>
/// <remarks>
/// The layout follows what the reader needs in order: what was scanned, what
/// was not reachable, a count per risk level, then the entries with their
/// reasons spelled out. The reasons are the point — a level without its
/// justification invites the reader to act on a number they do not understand.
/// </remarks>
public sealed class TextReportWriter : IReportWriter
{
    private const int RuleWidth = 78;

    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Text;

    /// <inheritdoc />
    public string Write(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var builder = new StringBuilder();

        WriteHeader(builder, result);
        WriteGaps(builder, result);
        WriteSummary(builder, result);
        WriteEntries(builder, result);
        WriteFooter(builder);

        return builder.ToString();
    }

    /// <inheritdoc />
    public string Write(BaselineDiff diff)
    {
        ArgumentNullException.ThrowIfNull(diff);

        var builder = new StringBuilder();

        builder.AppendLine("Hoong-systemScope - baseline comparison");
        builder.AppendLine(new string('=', RuleWidth));
        builder.AppendLine(Invariant($"Baseline taken : {diff.BaselineTakenAtUtc:u}"));
        builder.AppendLine(Invariant($"Current scan   : {diff.CurrentTakenAtUtc:u}"));
        builder.AppendLine();

        if (diff.IsEmpty)
        {
            builder.AppendLine(Invariant($"No changes. {diff.UnchangedCount} entries are identical in both scans."));
            return builder.ToString();
        }

        builder.AppendLine(Invariant(
            $"{diff.Added.Count} added, {diff.Removed.Count} removed, {diff.Modified.Count} modified, {diff.UnchangedCount} unchanged."));
        builder.AppendLine();

        WriteChangeSection(builder, "Added", diff.Added);
        WriteChangeSection(builder, "Modified", diff.Modified);
        WriteChangeSection(builder, "Removed", diff.Removed);

        return builder.ToString();
    }

    private static void WriteHeader(StringBuilder builder, ScanResult result)
    {
        builder.AppendLine("Hoong-systemScope - diagnostic report");
        builder.AppendLine(new string('=', RuleWidth));
        builder.AppendLine(Invariant($"Machine      : {result.Machine.MachineName}"));
        builder.AppendLine(Invariant($"Operating sys: {result.Machine.OperatingSystem} ({result.Machine.Architecture})"));
        builder.AppendLine(Invariant($"Scanned as   : {result.Machine.UserName}{(result.Machine.IsElevated ? " (elevated)" : " (not elevated)")}"));
        builder.AppendLine(Invariant($"Started      : {result.StartedAtUtc:u}"));
        builder.AppendLine(Invariant($"Duration     : {(result.CompletedAtUtc - result.StartedAtUtc).TotalSeconds:F1} s"));
        builder.AppendLine(Invariant($"Tool version : {result.ToolVersion}"));
        builder.AppendLine();
        builder.AppendLine("This is a diagnostic tool, not an antivirus product. It reports what is");
        builder.AppendLine("configured on this machine and explains why an entry looked unusual. It");
        builder.AppendLine("changes nothing and it cannot tell you that something is malicious.");
        builder.AppendLine();
    }

    /// <summary>
    /// States what the scan could not see. Printed before the findings, because
    /// a reader who does not know the report is incomplete will read absence as
    /// evidence.
    /// </summary>
    private static void WriteGaps(StringBuilder builder, ScanResult result)
    {
        if (result.Errors.Count == 0)
        {
            return;
        }

        builder.AppendLine("Coverage gaps");
        builder.AppendLine(new string('-', RuleWidth));

        foreach (var error in result.Errors.OrderByDescending(e => e.Severity))
        {
            builder.AppendLine(Invariant($"[{error.Severity}] {error.CollectorId}: {error.Message}"));

            if (error.Location is { Length: > 0 })
            {
                builder.AppendLine(Invariant($"          {error.Location}"));
            }
        }

        builder.AppendLine();
    }

    private static void WriteSummary(StringBuilder builder, ScanResult result)
    {
        var summary = result.Summary;
        if (summary is null)
        {
            return;
        }

        builder.AppendLine("Summary");
        builder.AppendLine(new string('-', RuleWidth));
        builder.AppendLine(Invariant($"Entries: {summary.TotalEntries}, missing files: {summary.MissingFileCount}"));
        builder.AppendLine();

        foreach (var level in Enum.GetValues<RiskLevel>().OrderByDescending(l => l))
        {
            var count = summary.ByRiskLevel.TryGetValue(level, out var value) ? value : 0;
            builder.AppendLine(Invariant($"  {level,-14} {count,5}"));
        }

        builder.AppendLine();

        foreach (var (category, count) in summary.ByCategory.OrderByDescending(p => p.Value))
        {
            builder.AppendLine(Invariant($"  {category,-28} {count,5}"));
        }

        builder.AppendLine();
    }

    private static void WriteEntries(StringBuilder builder, ScanResult result)
    {
        var ordered = ReportOrder.Sort(result.Entries).ToArray();

        if (ordered.Length == 0)
        {
            builder.AppendLine("No entries were collected.");
            return;
        }

        builder.AppendLine("Findings");
        builder.AppendLine(new string('-', RuleWidth));

        foreach (var entry in ordered)
        {
            WriteEntry(builder, entry);
        }
    }

    private static void WriteEntry(StringBuilder builder, ScanEntry entry)
    {
        builder.AppendLine();
        builder.AppendLine(Invariant($"[{entry.RiskLevel}/{entry.RiskScore}] {entry.Category}: {entry.Name}"));
        builder.AppendLine(Invariant($"  Location   : {entry.Location}"));

        if (entry.ExecutablePath is { Length: > 0 })
        {
            var existence = entry.FileExists switch
            {
                true => string.Empty,
                false => "  (file does not exist)",
                null => string.Empty,
            };

            builder.AppendLine(Invariant($"  File       : {entry.ExecutablePath}{existence}"));
        }

        if (entry.Arguments is { Length: > 0 })
        {
            builder.AppendLine(Invariant($"  Arguments  : {entry.Arguments}"));
        }

        if (entry.UserName is { Length: > 0 })
        {
            builder.AppendLine(Invariant($"  Runs as    : {entry.UserName}"));
        }

        if (entry.Publisher is { Length: > 0 })
        {
            builder.AppendLine(Invariant($"  Publisher  : {entry.Publisher}"));
        }

        if (entry.SignatureStatus != SignatureStatus.NotChecked)
        {
            var subject = entry.Signature?.SubjectName is { Length: > 0 } name ? $" ({name})" : string.Empty;
            builder.AppendLine(Invariant($"  Signature  : {entry.SignatureStatus}{subject}"));
        }

        if (entry.Sha256 is { Length: > 0 })
        {
            builder.AppendLine(Invariant($"  SHA-256    : {entry.Sha256}"));
        }

        if (entry.RiskReasons.Count == 0)
        {
            return;
        }

        builder.AppendLine("  Why this was rated:");

        foreach (var reason in entry.RiskReasons)
        {
            var sign = reason.ScoreDelta >= 0 ? "+" : string.Empty;
            builder.AppendLine(Invariant($"    {sign}{reason.ScoreDelta,-4} {reason.Title}"));

            if (reason.Detail is { Length: > 0 })
            {
                builder.AppendLine(Invariant($"          {reason.Detail}"));
            }
        }
    }

    private static void WriteChangeSection(
        StringBuilder builder,
        string title,
        IReadOnlyList<BaselineEntryChange> changes)
    {
        if (changes.Count == 0)
        {
            return;
        }

        builder.AppendLine(Invariant($"{title} ({changes.Count})"));
        builder.AppendLine(new string('-', RuleWidth));

        foreach (var change in changes)
        {
            var entry = change.After ?? change.Before;
            if (entry is null)
            {
                continue;
            }

            builder.AppendLine(Invariant($"[{entry.RiskLevel}/{entry.RiskScore}] {entry.Category}: {entry.Name}"));
            builder.AppendLine(Invariant($"  Location: {entry.Location}"));

            foreach (var field in change.Changes)
            {
                builder.AppendLine(Invariant($"  {field.Field}:"));
                builder.AppendLine(Invariant($"    before: {field.OldValue ?? "(none)"}"));
                builder.AppendLine(Invariant($"    after : {field.NewValue ?? "(none)"}"));
            }

            builder.AppendLine();
        }
    }

    private static void WriteFooter(StringBuilder builder)
    {
        builder.AppendLine();
        builder.AppendLine(new string('-', RuleWidth));
        builder.AppendLine("Nothing on this machine was modified. Hoong-systemScope does not delete");
        builder.AppendLine("files, remove registry entries, stop services or run anything it found.");
    }

    /// <summary>
    /// Formats an interpolated string invariantly. There is deliberately no
    /// overload taking a plain string: with one present, C# would bind every
    /// interpolation to it and the invariant formatting would silently never
    /// happen.
    /// </summary>
    private static string Invariant(FormattableString value) => value.ToString(CultureInfo.InvariantCulture);
}
