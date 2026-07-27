using HoongSystemScope.Collectors.Modules;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Tests;

public sealed class RegistryRunCollectorTests
{
    private const string MachineRun = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public async Task Reads_machine_and_user_run_values()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun)
            .WithValue("SecurityHealth", @"%SystemRoot%\System32\SecurityHealthSystray.exe");
        harness.Registry.AddKey(RegistryHiveKind.CurrentUser, MachineRun)
            .WithValue("Updater", @"""C:\Program Files\Vendor\updater.exe"" /background");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        Assert.Equal(2, entries.Count);

        var systray = entries.Single(e => e.Name == "SecurityHealth");
        Assert.Equal(ScanCategory.RegistryRun, systray.Category);
        Assert.Equal(@"C:\Windows\System32\SecurityHealthSystray.exe", systray.ExecutablePath);

        var updater = entries.Single(e => e.Name == "Updater");
        Assert.Equal(@"C:\Program Files\Vendor\updater.exe", updater.ExecutablePath);
        Assert.Equal("/background", updater.Arguments);
    }

    [Fact]
    public async Task Separates_run_once_into_its_own_category()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry
            .AddKey(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            .WithValue("Cleanup", @"C:\Windows\System32\cmd.exe /c del temp");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        Assert.Equal(ScanCategory.RegistryRunOnce, Assert.Single(entries).Category);
    }

    [Fact]
    public async Task Scans_both_registry_views_so_thirty_two_bit_entries_are_not_missed()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = true;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun, RegistryViewKind.Registry64)
            .WithValue("Native", @"C:\native.exe");
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun, RegistryViewKind.Registry32)
            .WithValue("Wow", @"C:\wow.exe");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        Assert.Contains(entries, e => e.Name == "Native");
        Assert.Contains(entries, e => e.Name == "Wow");
    }

    [Fact]
    public async Task Skips_empty_values()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun)
            .WithValue("Blank", "   ")
            .WithValue("Real", @"C:\real.exe");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        Assert.Equal("Real", Assert.Single(entries).Name);
    }

    [Fact]
    public async Task Records_a_diagnostic_instead_of_failing_when_a_key_is_not_readable()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun).WithValue("Ok", @"C:\ok.exe");
        harness.Registry.DenyAccess(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        // The readable part still comes back.
        Assert.Equal("Ok", Assert.Single(entries).Name);

        var error = Assert.Single(harness.Diagnostics.Errors);
        Assert.Equal(ScanErrorSeverity.Warning, error.Severity);
        Assert.Contains("denied", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Run elevated", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Reports_but_never_mounts_an_unloaded_user_hive()
    {
        var harness = new ScanHarness { Options = ScanOptions.Default with { IncludeAllUsers = true } };
        harness.Registry.SupportsWow64Views = false;
        harness.Environment.UserProfiles.Add(
            new UserProfile("S-1-5-21-1", "alice", @"C:\Users\alice", IsHiveLoaded: false));
        harness.Environment.UserProfiles.Add(
            new UserProfile("S-1-5-21-2", "bob", @"C:\Users\bob", IsHiveLoaded: true));
        harness.Registry.AddKey(RegistryHiveKind.Users, $@"S-1-5-21-2\{MachineRun}")
            .WithValue("BobTool", @"C:\bob.exe");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        Assert.Equal("BobTool", Assert.Single(entries).Name);

        var skipped = Assert.Single(harness.Diagnostics.Errors);
        Assert.Equal(ScanErrorSeverity.Information, skipped.Severity);
        Assert.Contains("does not mount hives", skipped.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Flags_an_unquoted_path_containing_spaces()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun)
            .WithValue("Sloppy", @"C:\Program Files\Vendor\app.exe -run");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("true", entry.Metadata[MetadataKeys.UnquotedPath]);
    }

    [Fact]
    public async Task Records_the_library_a_rundll32_entry_loads()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, MachineRun)
            .WithValue("Hidden", @"rundll32.exe C:\Users\bob\AppData\Local\Temp\payload.dll,Start");

        var entries = await ScanHarness.CollectAsync(new RegistryRunCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal(@"C:\Users\bob\AppData\Local\Temp\payload.dll", entry.Metadata[MetadataKeys.Rundll32Target]);
        Assert.Equal("Start", entry.Metadata[MetadataKeys.Rundll32EntryPoint]);
    }
}
