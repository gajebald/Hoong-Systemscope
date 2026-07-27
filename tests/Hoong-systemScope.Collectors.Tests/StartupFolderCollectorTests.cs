using HoongSystemScope.Collectors.Modules;

namespace HoongSystemScope.Collectors.Tests;

public sealed class StartupFolderCollectorTests
{
    private const string UserStartup =
        @"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

    [Fact]
    public async Task Resolves_a_shortcut_to_its_target()
    {
        var harness = new ScanHarness();
        harness.FileSystem
            .AddFile($@"{UserStartup}\Vendor.lnk")
            .AddFile(@"C:\Program Files\Vendor\app.exe");
        harness.Shortcuts.Add($@"{UserStartup}\Vendor.lnk", @"C:\Program Files\Vendor\app.exe", "--tray");

        var entries = await ScanHarness.CollectAsync(new StartupFolderCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("Vendor.lnk", entry.Name);
        Assert.Equal(@"C:\Program Files\Vendor\app.exe", entry.ExecutablePath);
        Assert.Equal("--tray", entry.Arguments);
        Assert.True(entry.FileExists);
    }

    [Fact]
    public async Task Reports_a_shortcut_whose_target_cannot_be_resolved()
    {
        // A dangling or crafted link is exactly the thing not to silently drop.
        var harness = new ScanHarness();
        harness.FileSystem.AddFile($@"{UserStartup}\Broken.lnk");

        var entries = await ScanHarness.CollectAsync(new StartupFolderCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("Broken.lnk", entry.Name);
        Assert.Null(entry.ExecutablePath);
    }

    [Fact]
    public async Task Reports_a_bare_executable_placed_in_the_folder()
    {
        var harness = new ScanHarness();
        harness.FileSystem.AddFile($@"{UserStartup}\dropper.exe");

        var entries = await ScanHarness.CollectAsync(new StartupFolderCollector(), harness.Build());

        Assert.Equal($@"{UserStartup}\dropper.exe", Assert.Single(entries).ExecutablePath);
    }

    [Fact]
    public async Task Ignores_desktop_ini()
    {
        var harness = new ScanHarness();
        harness.FileSystem
            .AddFile($@"{UserStartup}\desktop.ini", "[.ShellClassInfo]")
            .AddFile($@"{UserStartup}\real.exe");

        var entries = await ScanHarness.CollectAsync(new StartupFolderCollector(), harness.Build());

        Assert.Equal("real.exe", Assert.Single(entries).Name);
    }

    [Fact]
    public async Task Returns_nothing_when_the_folders_do_not_exist()
    {
        var entries = await ScanHarness.CollectAsync(new StartupFolderCollector(), new ScanHarness().Build());

        Assert.Empty(entries);
    }
}
