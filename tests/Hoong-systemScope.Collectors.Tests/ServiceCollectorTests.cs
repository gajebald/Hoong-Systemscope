using HoongSystemScope.Collectors.Modules;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Tests;

public sealed class ServiceCollectorTests
{
    [Fact]
    public async Task Reports_services_and_leaves_drivers_to_the_driver_collector()
    {
        var harness = new ScanHarness();
        harness.Services.Services.Add(new ServiceRecord
        {
            ServiceName = "Spooler",
            DisplayName = "Print Spooler",
            ImagePath = @"C:\Windows\System32\spoolsv.exe",
            Account = "LocalSystem",
            Kind = ServiceKind.Service,
            StartMode = ServiceStartMode.Automatic,
            IsRunning = true,
        });
        harness.Services.Services.Add(new ServiceRecord
        {
            ServiceName = "vendorflt",
            ImagePath = @"\??\C:\Windows\System32\drivers\vendorflt.sys",
            Kind = ServiceKind.Driver,
            StartMode = ServiceStartMode.Boot,
        });

        var services = await ScanHarness.CollectAsync(new ServiceCollector(), harness.Build());
        var drivers = await ScanHarness.CollectAsync(new DriverCollector(), harness.Build());

        var spooler = Assert.Single(services);
        Assert.Equal("Spooler", spooler.Name);
        Assert.Equal(ScanCategory.Service, spooler.Category);
        Assert.Equal("LocalSystem", spooler.UserName);
        Assert.Equal("Automatic", spooler.Metadata[MetadataKeys.ServiceStartMode]);
        Assert.Equal("true", spooler.Metadata[MetadataKeys.ServiceRunning]);
        Assert.Equal("Print Spooler", spooler.FileDescription);

        var driver = Assert.Single(drivers);
        Assert.Equal(ScanCategory.Driver, driver.Category);

        // The native object manager prefix must be gone, otherwise nothing
        // downstream can hash or verify the file.
        Assert.Equal(@"C:\Windows\System32\drivers\vendorflt.sys", driver.ExecutablePath);
    }

    [Fact]
    public async Task Marks_a_disabled_service_as_not_enabled()
    {
        var harness = new ScanHarness();
        harness.Services.Services.Add(new ServiceRecord
        {
            ServiceName = "Old",
            ImagePath = @"C:\old.exe",
            Kind = ServiceKind.Service,
            StartMode = ServiceStartMode.Disabled,
        });

        var entries = await ScanHarness.CollectAsync(new ServiceCollector(), harness.Build());

        Assert.False(Assert.Single(entries).IsEnabled);
    }

    [Fact]
    public async Task Carries_the_hosting_dll_of_a_shared_host_service()
    {
        // svchost.exe is Microsoft-signed; the DLL is the part worth inspecting.
        var harness = new ScanHarness();
        harness.Services.Services.Add(new ServiceRecord
        {
            ServiceName = "Themes",
            ImagePath = @"C:\Windows\System32\svchost.exe -k netsvcs",
            ServiceDll = @"C:\Windows\System32\themeservice.dll",
            Kind = ServiceKind.Service,
            StartMode = ServiceStartMode.Automatic,
        });

        var entries = await ScanHarness.CollectAsync(new ServiceCollector(), harness.Build());

        Assert.Equal(@"C:\Windows\System32\themeservice.dll", Assert.Single(entries).Metadata[MetadataKeys.ServiceDll]);
    }
}
