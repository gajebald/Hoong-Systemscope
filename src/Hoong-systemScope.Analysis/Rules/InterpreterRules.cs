using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Analysis.Rules;

/// <summary>
/// Flags autostart entries that hand control to a script interpreter or to one
/// of the signed Windows binaries commonly abused as a loader.
/// </summary>
/// <remarks>
/// Every program named here is a legitimate part of Windows and is signed by
/// Microsoft, which is exactly why they get used: judging such an entry by its
/// signature alone clears it. What makes it interesting is that a persistence
/// point runs an interpreter rather than an application.
/// </remarks>
public sealed class ScriptInterpreterRule : RiskRuleBase
{
    private static readonly Dictionary<string, (int Score, string Note)> Interpreters =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["powershell.exe"] = (18, "Windows PowerShell"),
            ["pwsh.exe"] = (18, "PowerShell"),
            ["cmd.exe"] = (12, "the command prompt"),
            ["wscript.exe"] = (20, "the Windows Script Host"),
            ["cscript.exe"] = (20, "the Windows Script Host"),
            ["mshta.exe"] = (30, "the HTML application host"),
            ["rundll32.exe"] = (18, "rundll32"),
            ["regsvr32.exe"] = (25, "regsvr32"),
            ["msiexec.exe"] = (10, "the installer engine"),
            ["installutil.exe"] = (25, "InstallUtil"),
            ["mshtml.dll"] = (20, "the HTML engine"),
            ["msbuild.exe"] = (25, "MSBuild"),
            ["cmstp.exe"] = (30, "the connection manager profile installer"),
            ["forfiles.exe"] = (20, "forfiles"),
            ["bitsadmin.exe"] = (25, "bitsadmin"),
            ["certutil.exe"] = (25, "certutil"),
        };

    private static readonly ScanCategory[] PersistenceCategories =
    [
        ScanCategory.RegistryRun,
        ScanCategory.RegistryRunOnce,
        ScanCategory.StartupFolder,
        ScanCategory.ScheduledTask,
        ScanCategory.Service,
        ScanCategory.WinlogonHook,
        ScanCategory.ImageFileExecutionOptions,
    ];

    /// <inheritdoc />
    public override string RuleId => "ScriptInterpreter";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (!PersistenceCategories.Contains(entry.Category) || string.IsNullOrWhiteSpace(entry.ExecutablePath))
        {
            return null;
        }

        var fileName = PathFacts.GetFileName(entry.ExecutablePath);
        if (!Interpreters.TryGetValue(fileName, out var interpreter))
        {
            return null;
        }

        return Reason(
            "RISK_SCRIPT_INTERPRETER",
            $"The entry starts {interpreter.Note} rather than an application.",
            interpreter.Score,
            entry.CommandLine ?? entry.ExecutablePath);
    }
}

/// <summary>
/// Flags command lines carrying the switches typical of a concealed script
/// invocation.
/// </summary>
/// <remarks>
/// Individually these are ordinary options. Together — hidden window, no
/// profile, execution policy bypassed, payload base64 encoded — they describe
/// something built not to be seen, which is why the rule scores the
/// combination rather than each flag.
/// </remarks>
public sealed class ObfuscatedCommandRule : RiskRuleBase
{
    private static readonly (string Token, int Score, string Description)[] Indicators =
    [
        ("-encodedcommand", 25, "a base64 encoded command"),
        ("-enc ", 25, "a base64 encoded command"),
        ("/enc ", 25, "a base64 encoded command"),
        ("-e ", 12, "a shortened encoded command switch"),
        ("-windowstyle hidden", 20, "a hidden window"),
        ("-w hidden", 20, "a hidden window"),
        ("-noprofile", 8, "no profile"),
        ("-nop ", 8, "no profile"),
        ("-executionpolicy bypass", 20, "a bypassed execution policy"),
        ("-ep bypass", 20, "a bypassed execution policy"),
        ("-noninteractive", 5, "non-interactive mode"),
        ("frombase64string", 25, "an inline base64 decode"),
        ("downloadstring", 30, "an inline download"),
        ("downloadfile", 30, "an inline download"),
        ("iex ", 25, "an inline expression evaluation"),
        ("invoke-expression", 25, "an inline expression evaluation"),
    ];

    /// <summary>Score above which the combination is reported at all.</summary>
    private const int ReportingFloor = 12;

    /// <inheritdoc />
    public override string RuleId => "ObfuscatedCommand";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        var commandLine = entry.CommandLine ?? entry.Arguments;
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        var haystack = commandLine.ToLowerInvariant();
        var score = 0;
        var found = new List<string>();

        foreach (var (token, tokenScore, description) in Indicators)
        {
            if (!haystack.Contains(token, StringComparison.Ordinal))
            {
                continue;
            }

            score += tokenScore;

            if (!found.Contains(description, StringComparer.Ordinal))
            {
                found.Add(description);
            }
        }

        if (score < ReportingFloor)
        {
            return null;
        }

        // Cap the contribution. Beyond a point, more switches do not make the
        // entry meaningfully more suspicious, and letting one rule dominate the
        // total would defeat the purpose of scoring several indicators.
        score = Math.Min(score, 55);

        return Reason(
            "RISK_OBFUSCATED_COMMAND",
            $"The command line uses {string.Join(", ", found)}.",
            score,
            commandLine);
    }
}

/// <summary>Flags the persistence points that are noteworthy simply by existing.</summary>
public sealed class SensitivePersistenceRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "SensitivePersistence";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context) => entry.Category switch
    {
        // An IFEO debugger redirects execution of another program entirely.
        // Legitimate uses exist but are rare and short-lived.
        ScanCategory.ImageFileExecutionOptions => Reason(
            "RISK_IFEO_DEBUGGER",
            "A debugger is registered for another program, so Windows starts this instead of it.",
            35,
            entry.Metadata.TryGetValue("ifeo.hijackedImage", out var image) ? image : entry.Name),

        // Both inject a library into other processes system-wide.
        ScanCategory.AppInitDll => Reason(
            "RISK_APPINIT_DLL",
            "The library is injected into other processes system-wide.",
            entry.IsEnabled == false ? 12 : 30,
            entry.ExecutablePath),

        // A non-default Winlogon hook runs before the shell does.
        ScanCategory.WinlogonHook when IsNonDefault(entry) => Reason(
            "RISK_WINLOGON_HOOK",
            "The Winlogon entry differs from the Windows default, so it runs at every logon.",
            30,
            entry.CommandLine),

        _ => null,
    };

    private static bool IsNonDefault(ScanEntry entry) =>
        entry.Metadata.TryGetValue("winlogon.isDefault", out var isDefault) && isDefault == "false";
}

/// <summary>Flags scheduled tasks configured to stay out of sight.</summary>
public sealed class HiddenTaskRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "HiddenTask";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (entry.Category != ScanCategory.ScheduledTask)
        {
            return null;
        }

        var isHidden = entry.Metadata.TryGetValue(MetadataKeys.TaskHidden, out var hidden) && hidden == "true";
        if (!isHidden)
        {
            return null;
        }

        var runsElevated =
            (entry.Metadata.TryGetValue(MetadataKeys.TaskRunLevel, out var runLevel) &&
             string.Equals(runLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase)) ||
            (entry.UserName is { } account && account.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase));

        // Windows ships plenty of hidden maintenance tasks, so hidden alone is
        // weak. Hidden *and* elevated is the combination worth surfacing.
        return runsElevated
            ? Reason(
                "RISK_HIDDEN_ELEVATED_TASK",
                "The task is hidden from the task scheduler UI and runs with elevated privileges.",
                25,
                entry.Location)
            : Reason(
                "RISK_HIDDEN_TASK",
                "The task is hidden from the task scheduler UI.",
                8,
                entry.Location);
    }
}

/// <summary>Flags hosts file entries that redirect rather than block.</summary>
public sealed class HostsRedirectRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "HostsRedirect";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (entry.Category != ScanCategory.HostsFile)
        {
            return null;
        }

        var isLoopback = !entry.Metadata.TryGetValue("hosts.isLoopback", out var loopback) || loopback == "true";
        var address = entry.Metadata.TryGetValue(MetadataKeys.HostsAddress, out var value) ? value : null;

        // A loopback mapping blocks a name; that is how ad blockers and update
        // blockers work and is worth listing but not alarming about. Pointing a
        // name at a real address is a different matter.
        return isLoopback
            ? Reason(
                "RISK_HOSTS_BLOCK",
                "The hosts file blocks this name locally.",
                4,
                address)
            : Reason(
                "RISK_HOSTS_REDIRECT",
                "The hosts file redirects this name to a specific address.",
                20,
                address);
    }
}
