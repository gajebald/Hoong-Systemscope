using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Core.Tests;

public sealed class EntryIdentityTests
{
    [Fact]
    public void Compute_is_deterministic()
    {
        var first = EntryIdentity.Compute(ScanCategory.RegistryRun, @"HKLM\Software\...\Run", "Updater");
        var second = EntryIdentity.Compute(ScanCategory.RegistryRun, @"HKLM\Software\...\Run", "Updater");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Compute_ignores_case_and_trailing_separators()
    {
        var first = EntryIdentity.Compute(ScanCategory.RegistryRun, @"HKLM\Software\Run\", "Updater");
        var second = EntryIdentity.Compute(ScanCategory.RegistryRun, @"hklm\software\run", "updater");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Compute_distinguishes_category_location_and_name()
    {
        var baseId = EntryIdentity.Compute(ScanCategory.RegistryRun, @"HKLM\Run", "Updater");

        Assert.NotEqual(baseId, EntryIdentity.Compute(ScanCategory.RegistryRunOnce, @"HKLM\Run", "Updater"));
        Assert.NotEqual(baseId, EntryIdentity.Compute(ScanCategory.RegistryRun, @"HKCU\Run", "Updater"));
        Assert.NotEqual(baseId, EntryIdentity.Compute(ScanCategory.RegistryRun, @"HKLM\Run", "Other"));
    }

    [Fact]
    public void Compute_produces_a_url_safe_fixed_length_id()
    {
        var id = EntryIdentity.Compute(ScanCategory.Service, @"HKLM\System\CurrentControlSet\Services", "Spooler");

        Assert.Equal(22, id.Length);
        Assert.DoesNotContain('+', id);
        Assert.DoesNotContain('/', id);
        Assert.DoesNotContain('=', id);
    }
}
