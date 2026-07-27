using HoongSystemScope.Collectors;
using HoongSystemScope.Core.Models;
using HoongSystemScope.TestSupport;

namespace HoongSystemScope.Collectors.Tests;

/// <summary>Assembles a scan context whose every dependency is a fake.</summary>
internal sealed class ScanHarness
{
    public FakeRegistry Registry { get; } = new();

    public FakeFileSystem FileSystem { get; } = new();

    public FakeEnvironment Environment { get; } = new();

    public FakeServiceCatalog Services { get; } = new();

    public FakeScheduledTaskProvider ScheduledTasks { get; } = new();

    public FakeProcessProvider Processes { get; } = new();

    public FakeShortcutResolver Shortcuts { get; } = new();

    public CollectorDiagnostics Diagnostics { get; } = new();

    public ScanOptions Options { get; set; } = ScanOptions.Default;

    public ScanContext Build() => new(
        Options,
        Registry,
        FileSystem,
        Environment,
        Services,
        ScheduledTasks,
        Processes,
        Shortcuts,
        FixedClock.Default,
        Diagnostics);

    public static async Task<List<ScanEntry>> CollectAsync(IScanCollector collector, ScanContext context)
    {
        var entries = new List<ScanEntry>();

        await foreach (var entry in collector.CollectAsync(context, CancellationToken.None))
        {
            entries.Add(entry);
        }

        return entries;
    }
}
