using HoongSystemScope.Core.Security;

namespace HoongSystemScope.Core.Tests;

public sealed class SensitiveLocationsTests
{
    [Theory]
    [InlineData(@"SAM")]
    [InlineData(@"SAM\SAM\Domains")]
    [InlineData(@"SECURITY\Policy\Secrets")]
    [InlineData(@"system\currentcontrolset\control\lsa\secrets")]
    [InlineData(@"SOFTWARE\Microsoft\Vault")]
    public void IsDeniedRegistryPath_blocks_credential_stores(string path) =>
        Assert.True(SensitiveLocations.IsDeniedRegistryPath(path));

    [Theory]
    [InlineData(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")]
    [InlineData(@"SYSTEM\CurrentControlSet\Services")]
    [InlineData(@"SAMPLE\Something")]
    [InlineData(null)]
    public void IsDeniedRegistryPath_allows_the_areas_the_tool_actually_scans(string? path) =>
        Assert.False(SensitiveLocations.IsDeniedRegistryPath(path));

    [Theory]
    [InlineData(@"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Microsoft\Protect\S-1-5-21")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default")]
    public void IsDeniedPath_blocks_browser_profiles_and_key_stores(string path) =>
        Assert.True(SensitiveLocations.IsDeniedPath(path));

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\app.lnk")]
    public void IsDeniedPath_allows_normal_scan_targets(string path) =>
        Assert.False(SensitiveLocations.IsDeniedPath(path));
}
