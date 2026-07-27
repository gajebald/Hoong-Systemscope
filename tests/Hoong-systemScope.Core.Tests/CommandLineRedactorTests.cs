using HoongSystemScope.Core.Security;

namespace HoongSystemScope.Core.Tests;

public sealed class CommandLineRedactorTests
{
    [Fact]
    public void Redact_leaves_ordinary_command_lines_untouched()
    {
        const string CommandLine = @"""C:\Program Files\Vendor\app.exe"" --minimized";

        Assert.Equal(CommandLine, CommandLineRedactor.Redact(CommandLine));
    }

    [Fact]
    public void Redact_truncates_an_encoded_powershell_payload_but_keeps_it_verifiable()
    {
        var payload = new string('A', 4096);
        var commandLine = $"powershell.exe -nop -w hidden -EncodedCommand {payload}";

        var redacted = CommandLineRedactor.Redact(commandLine);

        Assert.NotNull(redacted);

        // The indicators that make this suspicious survive.
        Assert.Contains("-EncodedCommand", redacted, StringComparison.Ordinal);
        Assert.Contains("-w hidden", redacted, StringComparison.Ordinal);

        // A bounded prefix of the payload survives as evidence, the rest does not.
        Assert.Contains(new string('A', CommandLineRedactor.RetainedPrefixLength), redacted, StringComparison.Ordinal);
        Assert.DoesNotContain(payload, redacted, StringComparison.Ordinal);

        // Length and digest make two reports comparable on the elided value.
        Assert.Contains("truncated: 4096 chars", redacted, StringComparison.Ordinal);
        Assert.Contains("sha256=", redacted, StringComparison.Ordinal);
        Assert.True(redacted.Length < commandLine.Length);
    }

    [Fact]
    public void Redact_keeps_long_paths_intact()
    {
        // Long is not the same as opaque. A deep path is still readable
        // evidence and must not be mangled.
        var commandLine = @"C:\Program Files\SomeVendor\WithAVeryLongProductName\AndASubdirectory\Deeper\app.exe";

        Assert.Equal(commandLine, CommandLineRedactor.Redact(commandLine));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Redact_passes_blank_input_through(string? input) =>
        Assert.Equal(input, CommandLineRedactor.Redact(input));
}
