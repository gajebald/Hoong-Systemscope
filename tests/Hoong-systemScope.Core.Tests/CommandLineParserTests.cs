using HoongSystemScope.Core.Text;
using HoongSystemScope.TestSupport;

namespace HoongSystemScope.Core.Tests;

public sealed class CommandLineParserTests
{
    private static CommandLineParser CreateParser(FakeFileSystem fileSystem, FakeEnvironment? environment = null) =>
        new(fileSystem, environment ?? new FakeEnvironment());

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_returns_empty_for_blank_input(string? input)
    {
        var parsed = CreateParser(new FakeFileSystem()).Parse(input);

        Assert.True(parsed.IsEmpty);
        Assert.Null(parsed.ExecutablePath);
    }

    [Fact]
    public void Parse_splits_quoted_path_from_arguments()
    {
        var parsed = CreateParser(new FakeFileSystem())
            .Parse("\"C:\\Program Files\\Vendor\\app.exe\" --minimized /background");

        Assert.Equal(@"C:\Program Files\Vendor\app.exe", parsed.ExecutablePath);
        Assert.Equal("--minimized /background", parsed.Arguments);
        Assert.True(parsed.WasQuoted);
        Assert.False(parsed.HasUnquotedPathWithSpaces);
    }

    [Fact]
    public void Parse_handles_quoted_path_without_arguments()
    {
        var parsed = CreateParser(new FakeFileSystem()).Parse("\"C:\\Tools\\app.exe\"");

        Assert.Equal(@"C:\Tools\app.exe", parsed.ExecutablePath);
        Assert.Null(parsed.Arguments);
    }

    [Fact]
    public void Parse_recovers_from_an_unterminated_quote()
    {
        var parsed = CreateParser(new FakeFileSystem()).Parse("\"C:\\Tools\\app.exe --run");

        Assert.Equal(@"C:\Tools\app.exe --run", parsed.ExecutablePath);
    }

    [Fact]
    public void Parse_splits_simple_unquoted_path()
    {
        var fileSystem = new FakeFileSystem().AddFile(@"C:\Tools\app.exe");

        var parsed = CreateParser(fileSystem).Parse(@"C:\Tools\app.exe -silent");

        Assert.Equal(@"C:\Tools\app.exe", parsed.ExecutablePath);
        Assert.Equal("-silent", parsed.Arguments);
        Assert.False(parsed.HasUnquotedPathWithSpaces);
    }

    [Fact]
    public void Parse_resolves_unquoted_path_containing_spaces_when_the_file_exists()
    {
        var fileSystem = new FakeFileSystem().AddFile(@"C:\Program Files\Vendor\app.exe");

        var parsed = CreateParser(fileSystem).Parse(@"C:\Program Files\Vendor\app.exe -x");

        Assert.Equal(@"C:\Program Files\Vendor\app.exe", parsed.ExecutablePath);
        Assert.Equal("-x", parsed.Arguments);
        Assert.True(parsed.HasUnquotedPathWithSpaces);
    }

    [Fact]
    public void Parse_prefers_the_shortest_existing_prefix_just_like_the_windows_loader()
    {
        // This is the unquoted service path hijack: both files exist, and
        // Windows would launch the shorter one. Reporting the same target the
        // system would actually run is what makes the finding meaningful.
        var fileSystem = new FakeFileSystem()
            .AddFile(@"C:\Program.exe")
            .AddFile(@"C:\Program Files\Vendor\app.exe");

        var parsed = CreateParser(fileSystem).Parse(@"C:\Program Files\Vendor\app.exe");

        Assert.Equal(@"C:\Program.exe", parsed.ExecutablePath);
        Assert.True(parsed.HasUnquotedPathWithSpaces);
    }

    [Fact]
    public void Parse_falls_back_to_the_executable_extension_when_nothing_exists()
    {
        // A broken autostart entry still has to report its intended target,
        // otherwise "file missing" findings point at a truncated path.
        var parsed = CreateParser(new FakeFileSystem())
            .Parse(@"C:\Program Files\Gone\ghost.exe --flag value");

        Assert.Equal(@"C:\Program Files\Gone\ghost.exe", parsed.ExecutablePath);
        Assert.Equal("--flag value", parsed.Arguments);
        Assert.True(parsed.HasUnquotedPathWithSpaces);
    }

    [Fact]
    public void Parse_appends_exe_when_the_extension_was_omitted()
    {
        var fileSystem = new FakeFileSystem().AddFile(@"C:\Tools\app.exe");

        var parsed = CreateParser(fileSystem).Parse(@"C:\Tools\app -q");

        Assert.Equal(@"C:\Tools\app.exe", parsed.ExecutablePath);
        Assert.Equal("-q", parsed.Arguments);
    }

    [Fact]
    public void Parse_expands_environment_variables()
    {
        var fileSystem = new FakeFileSystem().AddFile(@"C:\Windows\System32\rundll32.exe");

        var parsed = CreateParser(fileSystem).Parse(@"%SystemRoot%\System32\rundll32.exe shell32.dll,Control_RunDLL");

        Assert.Equal(@"C:\Windows\System32\rundll32.exe", parsed.ExecutablePath);
        Assert.Equal("shell32.dll,Control_RunDLL", parsed.Arguments);
    }

    [Fact]
    public void Parse_normalises_the_native_object_manager_prefix()
    {
        var parsed = CreateParser(new FakeFileSystem()).Parse(@"\??\C:\Windows\System32\drivers\vendor.sys");

        Assert.Equal(@"C:\Windows\System32\drivers\vendor.sys", parsed.ExecutablePath);
    }

    [Fact]
    public void Parse_resolves_systemroot_prefixed_driver_paths()
    {
        var parsed = CreateParser(new FakeFileSystem()).Parse(@"\SystemRoot\System32\drivers\vendor.sys");

        Assert.Equal(@"C:\Windows\System32\drivers\vendor.sys", parsed.ExecutablePath);
    }

    [Fact]
    public void Parse_resolves_driver_paths_stored_relative_to_the_windows_directory()
    {
        var parsed = CreateParser(new FakeFileSystem()).Parse(@"System32\drivers\vendor.sys");

        Assert.Equal(@"C:\Windows\System32\drivers\vendor.sys", parsed.ExecutablePath);
    }

    [Fact]
    public void ParseSyntaxOnly_does_not_touch_the_file_system()
    {
        var parsed = CommandLineParser.ParseSyntaxOnly(@"C:\Program Files\Vendor\app.exe -x");

        Assert.Equal(@"C:\Program", parsed.ExecutablePath);
        Assert.Equal(@"Files\Vendor\app.exe -x", parsed.Arguments);
    }

    [Theory]
    [InlineData(@"shell32.dll,Control_RunDLL", "shell32.dll", "Control_RunDLL")]
    [InlineData(@"C:\Temp\payload.dll,Start", @"C:\Temp\payload.dll", "Start")]
    [InlineData("\"C:\\Program Files\\x\\p.dll\",Run", @"C:\Program Files\x\p.dll", "Run")]
    [InlineData(@"C:\Temp\payload.dll", @"C:\Temp\payload.dll", null)]
    public void TryGetRundll32Target_extracts_the_loaded_library(string arguments, string expectedDll, string? expectedEntry)
    {
        var found = CommandLineParser.TryGetRundll32Target(
            @"C:\Windows\System32\rundll32.exe",
            arguments,
            out var dll,
            out var entryPoint);

        Assert.True(found);
        Assert.Equal(expectedDll, dll);
        Assert.Equal(expectedEntry, entryPoint);
    }

    [Fact]
    public void TryGetRundll32Target_ignores_other_executables()
    {
        var found = CommandLineParser.TryGetRundll32Target(
            @"C:\Windows\System32\cmd.exe",
            "/c whoami",
            out _,
            out _);

        Assert.False(found);
    }
}
