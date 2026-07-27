using HoongSystemScope.Analysis.Rules;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis.Tests;

public sealed class InterpreterRuleTests
{
    private static readonly RiskEvaluationContext Context = RiskEvaluationContext.Default;

    [Theory]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData(@"C:\Windows\System32\mshta.exe")]
    [InlineData(@"C:\Windows\System32\regsvr32.exe")]
    [InlineData(@"C:\Windows\System32\wscript.exe")]
    public void An_autostart_that_launches_an_interpreter_is_reported(string path)
    {
        var reason = new ScriptInterpreterRule().Evaluate(EntryBuilder.Create(executablePath: path), Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_SCRIPT_INTERPRETER", reason.Code);
    }

    [Fact]
    public void A_running_process_using_an_interpreter_is_not_a_persistence_finding()
    {
        // A PowerShell window the user opened is not persistence.
        var reason = new ScriptInterpreterRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.Process,
                executablePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void An_ordinary_application_is_not_reported() =>
        Assert.Null(new ScriptInterpreterRule().Evaluate(
            EntryBuilder.Create(executablePath: @"C:\Program Files\Vendor\app.exe"), Context));

    [Fact]
    public void A_concealed_powershell_invocation_scores_on_the_combination()
    {
        var reason = new ObfuscatedCommandRule().Evaluate(
            EntryBuilder.Create(
                commandLine: "powershell.exe -nop -w hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA"),
            Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_OBFUSCATED_COMMAND", reason.Code);
        Assert.True(reason.ScoreDelta >= RiskThresholds.Default.High);
        Assert.Contains("hidden window", reason.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void A_single_harmless_switch_is_not_enough()
    {
        // -NoProfile on its own is entirely ordinary.
        var reason = new ObfuscatedCommandRule().Evaluate(
            EntryBuilder.Create(commandLine: @"powershell.exe -NoProfile -File C:\Scripts\backup.ps1"),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void The_obfuscation_score_is_capped()
    {
        // Stacking every indicator must not let one rule swamp the total.
        var reason = new ObfuscatedCommandRule().Evaluate(
            EntryBuilder.Create(
                commandLine: "powershell -nop -w hidden -ep bypass -enc AAA -noninteractive " +
                             "FromBase64String DownloadString DownloadFile IEX Invoke-Expression"),
            Context);

        Assert.NotNull(reason);
        Assert.True(reason.ScoreDelta <= 55);
    }

    [Fact]
    public void An_ifeo_debugger_is_reported_on_its_own()
    {
        var reason = new SensitivePersistenceRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.ImageFileExecutionOptions,
                name: "sethc.exe",
                executablePath: @"C:\Windows\System32\cmd.exe",
                metadata: EntryBuilder.Metadata(("ifeo.hijackedImage", "sethc.exe"))),
            Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_IFEO_DEBUGGER", reason.Code);
        Assert.Equal("sethc.exe", reason.Detail);
    }

    [Fact]
    public void A_disabled_appinit_library_scores_lower_than_an_active_one()
    {
        var rule = new SensitivePersistenceRule();

        var active = rule.Evaluate(EntryBuilder.Create(category: ScanCategory.AppInitDll, isEnabled: true), Context);
        var disabled = rule.Evaluate(EntryBuilder.Create(category: ScanCategory.AppInitDll, isEnabled: false), Context);

        Assert.NotNull(active);
        Assert.NotNull(disabled);
        Assert.True(active.ScoreDelta > disabled.ScoreDelta);
    }

    [Fact]
    public void A_default_winlogon_value_is_not_reported()
    {
        var reason = new SensitivePersistenceRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.WinlogonHook,
                metadata: EntryBuilder.Metadata(("winlogon.isDefault", "true"))),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void A_hidden_elevated_task_scores_above_a_merely_hidden_one()
    {
        // Windows ships many hidden maintenance tasks, so hidden alone is weak.
        var rule = new HiddenTaskRule();

        var hiddenOnly = rule.Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.ScheduledTask,
                metadata: EntryBuilder.Metadata((MetadataKeys.TaskHidden, "true"))),
            Context);

        var hiddenElevated = rule.Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.ScheduledTask,
                userName: "SYSTEM",
                metadata: EntryBuilder.Metadata(
                    (MetadataKeys.TaskHidden, "true"),
                    (MetadataKeys.TaskRunLevel, "HighestAvailable"))),
            Context);

        Assert.NotNull(hiddenOnly);
        Assert.NotNull(hiddenElevated);
        Assert.Equal("RISK_HIDDEN_TASK", hiddenOnly.Code);
        Assert.Equal("RISK_HIDDEN_ELEVATED_TASK", hiddenElevated.Code);
        Assert.True(hiddenElevated.ScoreDelta > hiddenOnly.ScoreDelta);
    }

    [Fact]
    public void A_hosts_redirect_outweighs_a_hosts_block()
    {
        var rule = new HostsRedirectRule();

        var blocked = rule.Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.HostsFile,
                executablePath: null,
                metadata: EntryBuilder.Metadata(
                    ("hosts.isLoopback", "true"),
                    (MetadataKeys.HostsAddress, "0.0.0.0"))),
            Context);

        var redirected = rule.Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.HostsFile,
                executablePath: null,
                metadata: EntryBuilder.Metadata(
                    ("hosts.isLoopback", "false"),
                    (MetadataKeys.HostsAddress, "203.0.113.9"))),
            Context);

        Assert.NotNull(blocked);
        Assert.NotNull(redirected);
        Assert.Equal("RISK_HOSTS_BLOCK", blocked.Code);
        Assert.Equal("RISK_HOSTS_REDIRECT", redirected.Code);
        Assert.True(redirected.ScoreDelta > blocked.ScoreDelta);
    }
}
