using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Core.Tests;

public sealed class PathFactsTests
{
    private const string WindowsDirectory = @"C:\Windows";

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", true)]
    [InlineData(@"C:\Temp\script.ps1", true)]
    [InlineData(@"C:\Temp\notes.txt", false)]
    [InlineData(@"C:\Temp\archive", false)]
    [InlineData(null, false)]
    public void HasExecutableExtension_matches_the_expected_set(string? path, bool expected) =>
        Assert.Equal(expected, PathFacts.HasExecutableExtension(path));

    [Theory]
    [InlineData(@"\??\C:\Windows\x.sys", @"C:\Windows\x.sys")]
    [InlineData(@"\SystemRoot\System32\x.sys", @"C:\Windows\System32\x.sys")]
    [InlineData(@"System32\drivers\x.sys", @"C:\Windows\System32\drivers\x.sys")]
    [InlineData(@"C:\Windows\System32\x.sys", @"C:\Windows\System32\x.sys")]
    [InlineData(null, null)]
    public void NormalizeNativePath_rewrites_native_forms(string? input, string? expected) =>
        Assert.Equal(expected, PathFacts.NormalizeNativePath(input, WindowsDirectory));

    [Fact]
    public void Classify_recognises_the_system_directory()
    {
        var kind = PathFacts.Classify(@"C:\Windows\System32\svchost.exe", WindowsDirectory);

        Assert.True(kind.HasFlag(PathLocationKind.SystemDirectory));
        Assert.True(kind.HasFlag(PathLocationKind.WindowsDirectory));
        Assert.False(kind.HasFlag(PathLocationKind.UserProfile));
    }

    [Fact]
    public void Classify_recognises_a_temporary_appdata_location()
    {
        var kind = PathFacts.Classify(@"C:\Users\bob\AppData\Local\Temp\dropper.exe", WindowsDirectory);

        Assert.True(kind.HasFlag(PathLocationKind.UserProfile));
        Assert.True(kind.HasFlag(PathLocationKind.AppData));
        Assert.True(kind.HasFlag(PathLocationKind.Temporary));
    }

    [Fact]
    public void Classify_recognises_a_unc_path()
    {
        var kind = PathFacts.Classify(@"\\fileserver\share\tool.exe", WindowsDirectory);

        Assert.Equal(PathLocationKind.NetworkShare, kind);
    }

    [Fact]
    public void Classify_does_not_confuse_a_similarly_named_directory()
    {
        // "Temperature" starts with "Temp" but is not a temporary directory.
        var kind = PathFacts.Classify(@"C:\Data\Temperature\reader.exe", WindowsDirectory);

        Assert.False(kind.HasFlag(PathLocationKind.Temporary));
    }

    [Theory]
    [InlineData(@"C:\payload.exe", true)]
    [InlineData(@"C:\Tools\payload.exe", false)]
    [InlineData(@"C:\", false)]
    public void IsDriveRoot_detects_files_directly_in_a_drive_root(string path, bool expected) =>
        Assert.Equal(expected, PathFacts.IsDriveRoot(path));

    [Theory]
    [InlineData(@"C:\Temp\invoice.pdf.exe", true)]
    [InlineData(@"C:\Temp\photo.jpg.scr", true)]
    [InlineData(@"C:\Temp\setup.exe", false)]
    [InlineData(@"C:\Temp\my.app.exe", false)]
    public void HasMisleadingDoubleExtension_flags_document_lookalikes(string path, bool expected) =>
        Assert.Equal(expected, PathFacts.HasMisleadingDoubleExtension(path));

    [Fact]
    public void ContainsBidirectionalOverride_detects_the_right_to_left_trick()
    {
        Assert.True(PathFacts.ContainsBidirectionalOverride("invoice\u202Egnp.exe"));
        Assert.False(PathFacts.ContainsBidirectionalOverride("invoice.png"));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32", @"C:\Windows", true)]
    [InlineData(@"C:\Windows", @"C:\Windows", false)]
    [InlineData(@"C:\WindowsApps\x", @"C:\Windows", false)]
    [InlineData(@"c:\windows\system32\x.exe", @"C:\Windows", true)]
    public void IsUnder_compares_whole_segments(string path, string directory, bool expected) =>
        Assert.Equal(expected, PathFacts.IsUnder(path, directory));
}
