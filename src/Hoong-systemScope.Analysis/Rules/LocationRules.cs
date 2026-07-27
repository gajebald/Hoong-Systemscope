using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Analysis.Rules;

/// <summary>Flags autostart entries running out of a volatile or user-writable location.</summary>
public sealed class SuspiciousLocationRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "SuspiciousLocation";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (!HasInspectableFile(entry))
        {
            return null;
        }

        var location = PathFacts.Classify(entry.ExecutablePath, context.WindowsDirectory);

        // Ordered by how unusual the location is for something that survives a
        // reboot. Only the strongest match scores, so a path that is both
        // temporary and inside AppData is not counted twice.
        if (location.HasFlag(PathLocationKind.RecycleBin))
        {
            return Reason(
                "RISK_LOCATION_RECYCLE_BIN",
                "The program runs from the recycle bin.",
                45,
                entry.ExecutablePath);
        }

        if (location.HasFlag(PathLocationKind.Temporary))
        {
            return Reason(
                "RISK_LOCATION_TEMP",
                "The program runs from a temporary directory, which is unusual for something that persists.",
                25,
                entry.ExecutablePath);
        }

        if (location.HasFlag(PathLocationKind.Downloads))
        {
            return Reason(
                "RISK_LOCATION_DOWNLOADS",
                "The program runs straight out of a Downloads folder.",
                22,
                entry.ExecutablePath);
        }

        if (location.HasFlag(PathLocationKind.DriveRoot))
        {
            return Reason(
                "RISK_LOCATION_DRIVE_ROOT",
                "The program sits directly in the root of a drive.",
                20,
                entry.ExecutablePath);
        }

        if (location.HasFlag(PathLocationKind.NetworkShare))
        {
            return Reason(
                "RISK_LOCATION_NETWORK",
                "The program is loaded from a network share.",
                18,
                entry.ExecutablePath);
        }

        if (location.HasFlag(PathLocationKind.AppData))
        {
            return Reason(
                "RISK_LOCATION_APPDATA",
                "The program runs from AppData, a location any program can write to without elevation.",
                10,
                entry.ExecutablePath);
        }

        return null;
    }
}

/// <summary>
/// Flags a system-context entry whose binary lives in a directory that
/// standard users can write to.
/// </summary>
public sealed class WritableDirectoryRule : RiskRuleBase
{
    private static readonly string[] PrivilegedAccounts =
    [
        "LocalSystem",
        "NT AUTHORITY\\SYSTEM",
        "SYSTEM",
        "NT AUTHORITY\\LocalService",
        "NT AUTHORITY\\NetworkService",
    ];

    /// <inheritdoc />
    public override string RuleId => "WritableDirectory";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (!HasInspectableFile(entry) || !RunsPrivileged(entry))
        {
            return null;
        }

        var directory = GetDirectory(entry.ExecutablePath!);
        if (directory is null || !context.IsDirectoryWritableByStandardUsers(directory))
        {
            return null;
        }

        // Anyone who can replace the file gets to run code as SYSTEM at the
        // next start. That is a straightforward privilege escalation path.
        return Reason(
            "RISK_WRITABLE_DIRECTORY",
            "A program running with system privileges lives in a directory that standard users can write to.",
            35,
            directory);
    }

    private static bool RunsPrivileged(ScanEntry entry) =>
        entry.Category is ScanCategory.Service or ScanCategory.Driver ||
        (entry.UserName is { } account &&
         PrivilegedAccounts.Contains(account, StringComparer.OrdinalIgnoreCase));

    private static string? GetDirectory(string path)
    {
        var index = path.Replace('/', '\\').LastIndexOf('\\');
        return index <= 2 ? null : path[..index];
    }
}

/// <summary>Flags an unquoted service path containing spaces.</summary>
public sealed class UnquotedServicePathRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "UnquotedServicePath";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (entry.Category is not (ScanCategory.Service or ScanCategory.Driver))
        {
            return null;
        }

        if (!entry.Metadata.TryGetValue(MetadataKeys.UnquotedPath, out var flag) || flag != "true")
        {
            return null;
        }

        // Windows probes each space-delimited prefix in turn, so an attacker
        // who can create C:\Program.exe takes over a service configured as
        // C:\Program Files\Vendor\app.exe. A long-standing and still common
        // misconfiguration.
        return Reason(
            "RISK_UNQUOTED_SERVICE_PATH",
            "The service path contains spaces and is not quoted, so Windows may launch a different program.",
            30,
            entry.CommandLine);
    }
}

/// <summary>Flags names built to be misread by a human.</summary>
public sealed class DeceptiveNameRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "DeceptiveName";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        // A right-to-left override reverses how the rest of the name renders,
        // so "invoice<U+202E>gnp.exe" is displayed as "invoiceexe.png".
        if (PathFacts.ContainsBidirectionalOverride(entry.Name) ||
            PathFacts.ContainsBidirectionalOverride(entry.ExecutablePath))
        {
            return Reason(
                "RISK_BIDI_OVERRIDE",
                "The name contains a Unicode directional override, which makes it display differently than it reads.",
                50,
                entry.Name);
        }

        if (PathFacts.HasMisleadingDoubleExtension(entry.ExecutablePath))
        {
            return Reason(
                "RISK_DOUBLE_EXTENSION",
                "The file name pairs a document extension with an executable one.",
                35,
                entry.ExecutablePath);
        }

        return null;
    }
}
