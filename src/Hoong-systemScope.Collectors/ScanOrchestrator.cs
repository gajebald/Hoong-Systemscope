using System.Diagnostics;
using HoongSystemScope.Collectors.Enrichment;
using HoongSystemScope.Core.Models;
using Microsoft.Extensions.Logging;

namespace HoongSystemScope.Collectors;

/// <summary>Progress notification emitted while a scan runs.</summary>
/// <param name="CollectorId">The collector that just finished.</param>
/// <param name="CompletedCollectors">How many collectors have finished.</param>
/// <param name="TotalCollectors">How many collectors will run in total.</param>
/// <param name="EntryCount">How many entries the finished collector produced.</param>
public sealed record ScanProgress(string CollectorId, int CompletedCollectors, int TotalCollectors, int EntryCount);

/// <summary>
/// Runs the collectors and assembles a <see cref="ScanResult"/>.
/// </summary>
/// <remarks>
/// The orchestrator owns the two properties that matter for a diagnostic tool:
/// one failing collector never takes the scan down, and a cancelled scan still
/// hands back whatever was already gathered. A partial answer is useful; an
/// exception is not.
/// </remarks>
public sealed class ScanOrchestrator
{
    private readonly IReadOnlyList<IScanCollector> _collectors;
    private readonly ILogger<ScanOrchestrator> _logger;

    /// <summary>Creates an orchestrator over the given collectors.</summary>
    public ScanOrchestrator(IEnumerable<IScanCollector> collectors, ILogger<ScanOrchestrator> logger)
    {
        ArgumentNullException.ThrowIfNull(collectors);
        ArgumentNullException.ThrowIfNull(logger);

        _collectors = collectors.ToArray();
        _logger = logger;
    }

    /// <summary>All registered collectors, in registration order.</summary>
    public IReadOnlyList<IScanCollector> Collectors => _collectors;

    /// <summary>Runs every selected collector and enriches the results.</summary>
    /// <param name="context">Access to the machine plus the scan options.</param>
    /// <param name="enricher">Fills in hash, publisher and signature.</param>
    /// <param name="toolVersion">Version recorded in the result.</param>
    /// <param name="progress">Optional progress sink.</param>
    /// <param name="cancellationToken">Cancels the scan; partial results are still returned.</param>
    public async Task<ScanResult> RunAsync(
        ScanContext context,
        EntryEnricher enricher,
        string toolVersion,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(enricher);

        var startedAt = context.Clock.UtcNow;
        var selected = _collectors.Where(c => context.Options.IncludesCategory(c.Category)).ToArray();
        var skipped = _collectors.Except(selected).ToArray();

        var machine = context.Environment.GetMachineInfo();
        WarnAboutMissingElevation(context, selected, machine);

        var entries = new List<ScanEntry>();
        var runInfos = new List<CollectorRunInfo>();
        var completed = 0;

        // Collectors are run sequentially while their entries are enriched
        // concurrently. The collectors themselves are I/O bound on the registry
        // and on COM, where parallelism buys little and costs determinism;
        // the file work behind them is where the time actually goes.
        foreach (var collector in selected)
        {
            var stopwatch = Stopwatch.StartNew();
            var collected = new List<ScanEntry>();
            var succeeded = true;

            try
            {
                await foreach (var entry in collector.CollectAsync(context, cancellationToken).ConfigureAwait(false))
                {
                    collected.Add(entry);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Scan cancelled while running collector {CollectorId}.", collector.Id);
                stopwatch.Stop();
                runInfos.Add(CreateRunInfo(collector, collected.Count, stopwatch.Elapsed, succeeded: false));
                entries.AddRange(await EnrichAllAsync(collected, enricher, context, CancellationToken.None)
                    .ConfigureAwait(false));
                break;
            }
#pragma warning disable CA1031 // A failing collector must never take the scan down.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                succeeded = false;
                _logger.LogError(ex, "Collector {CollectorId} failed.", collector.Id);

                context.Diagnostics.Report(new ScanError
                {
                    CollectorId = collector.Id,
                    Severity = ScanErrorSeverity.Error,
                    Message = $"Collector '{collector.Id}' failed: {ex.Message}",
                    ExceptionType = ex.GetType().Name,
                });
            }

            stopwatch.Stop();

            var enriched = await EnrichAllAsync(collected, enricher, context, cancellationToken).ConfigureAwait(false);
            entries.AddRange(enriched);

            runInfos.Add(CreateRunInfo(collector, enriched.Count, stopwatch.Elapsed, succeeded));

            completed++;
            progress?.Report(new ScanProgress(collector.Id, completed, selected.Length, enriched.Count));
        }

        foreach (var collector in skipped)
        {
            runInfos.Add(CreateRunInfo(collector, 0, TimeSpan.Zero, succeeded: true) with { Skipped = true });
        }

        return new ScanResult
        {
            SchemaVersion = ScanResult.CurrentSchemaVersion,
            ToolVersion = toolVersion,
            Machine = machine,
            StartedAtUtc = startedAt,
            CompletedAtUtc = context.Clock.UtcNow,
            Entries = entries,
            Errors = (context.Diagnostics as CollectorDiagnostics)?.Errors ?? [],
            Collectors = runInfos,
        };
    }

    private static async Task<List<ScanEntry>> EnrichAllAsync(
        List<ScanEntry> entries,
        EntryEnricher enricher,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        if (entries.Count == 0)
        {
            return entries;
        }

        var results = new ScanEntry[entries.Count];
        var parallelism = Math.Max(1, context.Options.MaxDegreeOfParallelism);

        await Parallel.ForAsync(
            0,
            entries.Count,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = parallelism,
                CancellationToken = cancellationToken,
            },
            async (index, token) => results[index] = await enricher
                .EnrichAsync(entries[index], token)
                .ConfigureAwait(false)).ConfigureAwait(false);

        return [.. results];
    }

    private static CollectorRunInfo CreateRunInfo(
        IScanCollector collector,
        int entryCount,
        TimeSpan duration,
        bool succeeded) =>
        new()
        {
            CollectorId = collector.Id,
            Category = collector.Category,
            EntryCount = entryCount,
            Duration = duration,
            Succeeded = succeeded,
        };

    /// <summary>
    /// Says up front which collectors will see only a part of the system,
    /// rather than letting the user discover the gap by comparing two reports.
    /// </summary>
    private static void WarnAboutMissingElevation(
        ScanContext context,
        IReadOnlyList<IScanCollector> selected,
        MachineInfo machine)
    {
        if (machine.IsElevated)
        {
            return;
        }

        foreach (var collector in selected.Where(c => c.RequiresElevation))
        {
            context.Diagnostics.Report(new ScanError
            {
                CollectorId = collector.Id,
                Severity = ScanErrorSeverity.Information,
                Message = $"Collector '{collector.Id}' returns incomplete results without administrative rights.",
            });
        }
    }
}
