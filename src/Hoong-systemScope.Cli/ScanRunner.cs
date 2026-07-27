using System.Reflection;
using System.Runtime.Versioning;
using HoongSystemScope.Analysis;
using HoongSystemScope.Collectors;
using HoongSystemScope.Collectors.Enrichment;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Export;
using Microsoft.Extensions.DependencyInjection;

namespace HoongSystemScope.Cli;

/// <summary>
/// Ties the collectors, the risk engine and the exporters together for one
/// command invocation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ScanRunner
{
    private readonly IServiceProvider _services;

    /// <summary>Creates a runner over a configured container.</summary>
    public ScanRunner(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _services = services;
    }

    /// <summary>Version reported in every scan result.</summary>
    public static string ToolVersion { get; } =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>Runs a scan and scores the result.</summary>
    public async Task<ScanResult> ScanAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var diagnostics = new CollectorDiagnostics();
        var fileSystem = _services.GetRequiredService<IFileSystemProbe>();
        var environment = _services.GetRequiredService<IEnvironmentProbe>();

        var context = new ScanContext(
            options,
            _services.GetRequiredService<IRegistryReader>(),
            fileSystem,
            environment,
            _services.GetRequiredService<IServiceCatalog>(),
            _services.GetRequiredService<IScheduledTaskProvider>(),
            _services.GetRequiredService<IProcessProvider>(),
            _services.GetRequiredService<IShortcutResolver>(),
            _services.GetRequiredService<ISystemClock>(),
            diagnostics);

        var cache = new FileFactsCache(
            fileSystem,
            _services.GetRequiredService<IFileMetadataProvider>(),
            _services.GetRequiredService<IHashProvider>(),
            _services.GetRequiredService<ISignatureVerifier>(),
            options);

        var result = await _services.GetRequiredService<ScanOrchestrator>()
            .RunAsync(context, new EntryEnricher(cache), ToolVersion, progress, cancellationToken)
            .ConfigureAwait(false);

        var riskContext = new RiskEvaluationContext(
            environment.WindowsDirectory,
            fileSystem.IsDirectoryWritableByStandardUsers);

        var scored = _services.GetRequiredService<RiskEngine>().Evaluate(result, riskContext);

        return ApplyMinimumRiskLevel(scored, options.MinimumRiskLevel);
    }

    /// <summary>Renders a scan result in the requested format.</summary>
    public string Render(ScanResult result, ReportFormat format) =>
        SelectWriter(format).Write(result);

    /// <summary>Renders a baseline comparison in the requested format.</summary>
    public string Render(BaselineDiff diff, ReportFormat format) =>
        SelectWriter(format).Write(diff);

    private IReportWriter SelectWriter(ReportFormat format) =>
        _services.GetServices<IReportWriter>().First(w => w.Format == format);

    /// <summary>
    /// Drops entries below the threshold, then recomputes the summary so the
    /// counts describe what the report actually contains.
    /// </summary>
    private static ScanResult ApplyMinimumRiskLevel(ScanResult result, RiskLevel minimum)
    {
        if (minimum == RiskLevel.Informational)
        {
            return result;
        }

        var kept = result.Entries.Where(e => e.RiskLevel >= minimum).ToArray();

        return result with
        {
            Entries = kept,
            Summary = ScanSummaryBuilder.Build(kept),
        };
    }
}
