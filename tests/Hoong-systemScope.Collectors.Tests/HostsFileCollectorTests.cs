using HoongSystemScope.Collectors.Modules;

namespace HoongSystemScope.Collectors.Tests;

public sealed class HostsFileCollectorTests
{
    private const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";

    [Fact]
    public async Task Parses_entries_and_ignores_comments_and_blank_lines()
    {
        var harness = new ScanHarness();
        harness.FileSystem.AddFile(HostsPath, """
            # Copyright (c) 1993-2009 Microsoft Corp.

            127.0.0.1       localhost
            0.0.0.0 update.vendor.example   # blocked
            10.20.30.40     intranet.corp.example
            """);

        var entries = await ScanHarness.CollectAsync(new HostsFileCollector(), harness.Build());

        Assert.Equal(3, entries.Count);

        var blocked = entries.Single(e => e.Name == "update.vendor.example");
        Assert.Equal("0.0.0.0", blocked.Metadata[MetadataKeys.HostsAddress]);
        Assert.Equal("true", blocked.Metadata["hosts.isLoopback"]);

        var redirected = entries.Single(e => e.Name == "intranet.corp.example");
        Assert.Equal("10.20.30.40", redirected.Metadata[MetadataKeys.HostsAddress]);
        Assert.Equal("false", redirected.Metadata["hosts.isLoopback"]);
    }

    [Fact]
    public async Task Handles_several_names_on_one_line()
    {
        var harness = new ScanHarness();
        harness.FileSystem.AddFile(HostsPath, "127.0.0.1 a.example b.example c.example");

        var entries = await ScanHarness.CollectAsync(new HostsFileCollector(), harness.Build());

        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal("127.0.0.1", e.Metadata[MetadataKeys.HostsAddress]));
    }

    [Fact]
    public async Task Returns_nothing_when_the_file_is_absent()
    {
        var entries = await ScanHarness.CollectAsync(new HostsFileCollector(), new ScanHarness().Build());

        Assert.Empty(entries);
        Assert.Empty(new ScanHarness().Diagnostics.Errors);
    }
}
