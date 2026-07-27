using HoongSystemScope.Collectors.Modules;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Tests;

public sealed class RegistryHijackCollectorTests
{
    private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string IfeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    [Fact]
    public async Task Winlogon_marks_a_default_userinit_as_default()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, WinlogonPath)
            .WithValue("Userinit", @"C:\Windows\system32\userinit.exe,")
            .WithValue("Shell", "explorer.exe");

        var entries = await ScanHarness.CollectAsync(new WinlogonCollector(), harness.Build());

        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.Equal("true", e.Metadata["winlogon.isDefault"]));
    }

    [Fact]
    public async Task Winlogon_detects_a_program_appended_to_userinit()
    {
        // Appending keeps the login working, which is exactly why this is easy
        // to overlook.
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, WinlogonPath)
            .WithValue("Userinit", @"C:\Windows\system32\userinit.exe,C:\Temp\evil.exe");

        var entries = await ScanHarness.CollectAsync(new WinlogonCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("false", entry.Metadata["winlogon.isDefault"]);
        Assert.Contains("evil.exe", entry.CommandLine, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Winlogon_reads_the_notify_handlers()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, WinlogonPath);
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, $@"{WinlogonPath}\Notify\vendor")
            .WithValue("DllName", @"C:\Windows\System32\vendorhook.dll");

        var entries = await ScanHarness.CollectAsync(new WinlogonCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal(@"Notify\vendor", entry.Name);
        Assert.Equal(@"C:\Windows\System32\vendorhook.dll", entry.ExecutablePath);
    }

    [Fact]
    public async Task AppInit_splits_the_library_list_and_carries_the_master_switch()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
            .WithValue("AppInit_DLLs", @"C:\Windows\System32\a.dll,C:\Temp\b.dll")
            .WithValue("LoadAppInit_DLLs", RegistryValueKind.DWord, 0);

        var entries = await ScanHarness.CollectAsync(new AppInitDllsCollector(), harness.Build());

        Assert.Equal(2, entries.Count);

        // The list stays populated even when loading is switched off, so the
        // switch has to travel with the entry rather than suppress it.
        Assert.All(entries, e => Assert.False(e.IsEnabled));
        Assert.All(entries, e => Assert.Equal("False", e.Metadata["appInit.loadEnabled"]));
    }

    [Fact]
    public async Task Ifeo_reports_only_keys_that_actually_redirect_execution()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, IfeoPath);

        // Mitigation policy only: not a hijack, must not be reported.
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, $@"{IfeoPath}\chrome.exe")
            .WithValue("MitigationOptions", RegistryValueKind.Binary, new byte[] { 1 });

        // The sticky keys backdoor.
        harness.Registry.AddKey(RegistryHiveKind.LocalMachine, $@"{IfeoPath}\sethc.exe")
            .WithValue("Debugger", @"C:\Windows\System32\cmd.exe");

        var entries = await ScanHarness.CollectAsync(new ImageFileExecutionOptionsCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("sethc.exe", entry.Name);
        Assert.Equal("Debugger", entry.Metadata["ifeo.kind"]);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", entry.ExecutablePath);
    }

    [Fact]
    public async Task Ifeo_reports_a_silent_process_exit_monitor()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(
                RegistryHiveKind.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe")
            .WithValue("MonitorProcess", @"C:\Temp\watch.exe");

        var entries = await ScanHarness.CollectAsync(new ImageFileExecutionOptionsCollector(), harness.Build());

        Assert.Equal("SilentProcessExit", Assert.Single(entries).Metadata["ifeo.kind"]);
    }

    [Fact]
    public async Task Shell_extension_resolves_the_class_identifier_to_a_library()
    {
        const string Clsid = "{11111111-2222-3333-4444-555555555555}";

        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry
            .AddKey(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")
            .WithValue(Clsid, "Vendor Overlay Handler");
        harness.Registry
            .AddKey(RegistryHiveKind.ClassesRoot, $@"CLSID\{Clsid}\InProcServer32")
            .WithValue(string.Empty, @"C:\Program Files\Vendor\overlay.dll")
            .WithValue("ThreadingModel", "Apartment");

        var entries = await ScanHarness.CollectAsync(new ShellExtensionCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("Vendor Overlay Handler", entry.Name);
        Assert.Equal(@"C:\Program Files\Vendor\overlay.dll", entry.ExecutablePath);
        Assert.Equal(Clsid, entry.Metadata[MetadataKeys.ClassId]);
        Assert.Equal("Apartment", entry.Metadata[MetadataKeys.ThreadingModel]);
    }

    [Fact]
    public async Task Winsock_reports_providers_that_declare_a_library()
    {
        var harness = new ScanHarness();
        harness.Registry.SupportsWow64Views = false;
        harness.Registry.AddKey(
                RegistryHiveKind.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64\000000000001")
            .WithValue("LibraryPath", @"%SystemRoot%\system32\mswsock.dll")
            .WithValue("DisplayString", "MSAFD Tcpip [TCP/IP]");

        var entries = await ScanHarness.CollectAsync(new WinsockProviderCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("MSAFD Tcpip [TCP/IP]", entry.Name);
        Assert.Equal(@"C:\Windows\system32\mswsock.dll", entry.ExecutablePath);
        Assert.Equal("Protocol", entry.Metadata["winsock.catalog"]);
    }
}
