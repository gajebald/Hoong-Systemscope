using System.Runtime.CompilerServices;
using HoongSystemScope.Collectors.Enrichment;
using HoongSystemScope.Core.Models;
using HoongSystemScope.TestSupport;
using Microsoft.Extensions.Logging.Abstractions;

namespace HoongSystemScope.Collectors.Tests;

public sealed class ScanOrchestratorTests
{
    private sealed class StubCollector : CollectorBase
    {
        private readonly IReadOnlyList<ScanEntry> _entries;
        private readonly Exception? _failure;

        public StubCollector(
            string id,
            ScanCategory category,
            IReadOnlyList<ScanEntry>? entries = null,
            Exception? failure = null,
            bool requiresElevation = false)
        {
            Id = id;
            Category = category;
            RequiresElevation = requiresElevation;
            _entries = entries ?? [];
            _failure = failure;
        }

        public override string Id { get; }

        public override string Description => "Stub collector.";

        public override ScanCategory Category { get; }

        public override bool RequiresElevation { get; }

        public override async IAsyncEnumerable<ScanEntry> CollectAsync(
            ScanContext context,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();

            if (_failure is not null)
            {
                throw _failure;
            }

            foreach (var entry in _entries)
            {
                yield return entry;
            }
        }
    }

    private static ScanEntry Entry(string name, string? path) => new()
    {
        Id = name,
        Category = ScanCategory.RegistryRun,
        Name = name,
        Location = @"HKLM\Run",
        ExecutablePath = path,
        CollectedAtUtc = FixedClock.Default.UtcNow,
    };

    private static (ScanOrchestrator Orchestrator, EntryEnricher Enricher, FakeHashProvider Hashes, FakeSignatureVerifier Signatures)
        CreateSubject(ScanHarness harness, params IScanCollector[] collectors)
    {
        var hashes = new FakeHashProvider();
        var signatures = new FakeSignatureVerifier();
        var cache = new FileFactsCache(
            harness.FileSystem,
            new FakeFileMetadataProvider(),
            hashes,
            signatures,
            harness.Options);

        return (
            new ScanOrchestrator(collectors, NullLogger<ScanOrchestrator>.Instance),
            new EntryEnricher(cache),
            hashes,
            signatures);
    }

    [Fact]
    public async Task A_failing_collector_does_not_take_the_scan_down()
    {
        var harness = new ScanHarness();
        var (orchestrator, enricher, _, _) = CreateSubject(
            harness,
            new StubCollector("broken", ScanCategory.Service, failure: new InvalidOperationException("boom")),
            new StubCollector("working", ScanCategory.RegistryRun, [Entry("Ok", null)]));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        Assert.Equal("Ok", Assert.Single(result.Entries).Name);

        var error = Assert.Single(result.Errors);
        Assert.Equal("broken", error.CollectorId);
        Assert.Equal(ScanErrorSeverity.Error, error.Severity);
        Assert.Equal("InvalidOperationException", error.ExceptionType);
        Assert.True(result.IsPartial);

        // The failure is visible in the per-collector bookkeeping too.
        Assert.False(result.Collectors.Single(c => c.CollectorId == "broken").Succeeded);
    }

    [Fact]
    public async Task Errors_never_carry_a_stack_trace()
    {
        // A report is routinely shared for help. Type and message are enough to
        // diagnose; a stack trace only leaks local paths.
        var harness = new ScanHarness();
        var (orchestrator, enricher, _, _) = CreateSubject(
            harness,
            new StubCollector("broken", ScanCategory.Service, failure: new InvalidOperationException("boom")));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        var error = Assert.Single(result.Errors);
        Assert.DoesNotContain("at Hoong", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(".cs:line", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Selecting_a_category_skips_the_other_collectors()
    {
        var harness = new ScanHarness
        {
            Options = ScanOptions.Default with
            {
                Categories = new HashSet<ScanCategory> { ScanCategory.RegistryRun },
            },
        };

        var (orchestrator, enricher, _, _) = CreateSubject(
            harness,
            new StubCollector("run", ScanCategory.RegistryRun, [Entry("Ok", null)]),
            new StubCollector("services", ScanCategory.Service, [Entry("Svc", null)]));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        Assert.Equal("Ok", Assert.Single(result.Entries).Name);
        Assert.True(result.Collectors.Single(c => c.CollectorId == "services").Skipped);
    }

    [Fact]
    public async Task Warns_up_front_when_a_collector_needs_elevation_it_does_not_have()
    {
        var harness = new ScanHarness();
        harness.Environment.Machine = harness.Environment.Machine with { IsElevated = false };

        var (orchestrator, enricher, _, _) = CreateSubject(
            harness,
            new StubCollector("services", ScanCategory.Service, requiresElevation: true));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        var notice = Assert.Single(result.Errors);
        Assert.Equal(ScanErrorSeverity.Information, notice.Severity);
        Assert.Contains("administrative rights", notice.Message, StringComparison.Ordinal);
        Assert.False(result.IsPartial);
    }

    [Fact]
    public async Task Records_the_machine_and_the_schema_version()
    {
        var harness = new ScanHarness();
        var (orchestrator, enricher, _, _) = CreateSubject(harness);

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "9.9.9");

        Assert.Equal(ScanResult.CurrentSchemaVersion, result.SchemaVersion);
        Assert.Equal("9.9.9", result.ToolVersion);
        Assert.Equal("TESTMACHINE", result.Machine.MachineName);
    }

    [Fact]
    public async Task Hashes_and_verifies_each_distinct_file_only_once()
    {
        // Forty services backed by the same svchost.exe must not mean forty
        // Authenticode round trips.
        var harness = new ScanHarness();
        harness.FileSystem.AddFile(@"C:\Windows\System32\svchost.exe");

        var entries = Enumerable
            .Range(0, 40)
            .Select(i => Entry($"Service{i}", @"C:\Windows\System32\svchost.exe"))
            .ToList();

        var (orchestrator, enricher, hashes, signatures) = CreateSubject(
            harness,
            new StubCollector("run", ScanCategory.RegistryRun, entries));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        Assert.Equal(40, result.Entries.Count);
        Assert.Equal(1, hashes.ComputeCount);
        Assert.Equal(1, signatures.VerifyCount);
    }

    [Fact]
    public async Task Skips_hashing_and_verification_when_they_are_switched_off()
    {
        var harness = new ScanHarness
        {
            Options = ScanOptions.Default with { ComputeHashes = false, VerifySignatures = false },
        };
        harness.FileSystem.AddFile(@"C:\app.exe");

        var (orchestrator, enricher, hashes, signatures) = CreateSubject(
            harness,
            new StubCollector("run", ScanCategory.RegistryRun, [Entry("App", @"C:\app.exe")]));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        Assert.Equal(0, hashes.ComputeCount);
        Assert.Equal(0, signatures.VerifyCount);
        Assert.Equal(SignatureStatus.NotChecked, Assert.Single(result.Entries).SignatureStatus);
    }

    [Fact]
    public async Task A_missing_file_is_reported_rather_than_dropped()
    {
        var harness = new ScanHarness();

        var (orchestrator, enricher, _, _) = CreateSubject(
            harness,
            new StubCollector("run", ScanCategory.RegistryRun, [Entry("Ghost", @"C:\gone\ghost.exe")]));

        var result = await orchestrator.RunAsync(harness.Build(), enricher, "test");

        var entry = Assert.Single(result.Entries);
        Assert.False(entry.FileExists);
        Assert.Equal(SignatureStatus.FileNotFound, entry.SignatureStatus);
    }

    [Fact]
    public async Task Inspects_the_rundll32_target_rather_than_rundll32_itself()
    {
        var harness = new ScanHarness();
        harness.FileSystem
            .AddFile(@"C:\Windows\System32\rundll32.exe")
            .AddFile(@"C:\Temp\payload.dll");

        var entry = Entry("Hidden", @"C:\Windows\System32\rundll32.exe") with
        {
            Metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                [MetadataKeys.Rundll32Target] = @"C:\Temp\payload.dll",
            },
        };

        var hashes = new FakeHashProvider().Add(@"C:\Temp\payload.dll", "abc123");
        var cache = new FileFactsCache(
            harness.FileSystem,
            new FakeFileMetadataProvider(),
            hashes,
            new FakeSignatureVerifier(),
            harness.Options);

        var enriched = await new EntryEnricher(cache).EnrichAsync(entry, CancellationToken.None);

        Assert.Equal("abc123", enriched.Sha256);
    }
}
