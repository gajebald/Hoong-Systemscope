using System.Globalization;
using System.Runtime.Versioning;
using HoongSystemScope.Collectors;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Export;
using HoongSystemScope.ViewModels;

namespace HoongSystemScope.App;

/// <summary>
/// Connects the desktop front end to the scanning half of the tool.
/// </summary>
/// <remarks>
/// Lives in the application layer rather than in the WPF project so that it is
/// compiled and type checked by any build agent, leaving only XAML and a thin
/// code-behind that genuinely need Windows.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class ScanService : IScanService
{
    private readonly ScanRunner _runner;

    /// <summary>Creates the adapter over a scan runner.</summary>
    public ScanService(ScanRunner runner)
    {
        ArgumentNullException.ThrowIfNull(runner);
        _runner = runner;
    }

    /// <inheritdoc />
    public Task<ScanResult> ScanAsync(
        ScanOptions options,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken cancellationToken)
    {
        // Translate the orchestrator's progress into the view model's shape, so
        // the presentation layer never has to reference the collectors.
        var adapter = progress is null
            ? null
            : new SynchronousProgress<ScanProgress>(p => progress.Report(new ScanProgressUpdate(
                string.Create(CultureInfo.InvariantCulture, $"{p.CollectorId} ({p.EntryCount} entries)"),
                p.CompletedCollectors,
                p.TotalCollectors)));

        return _runner.ScanAsync(options, adapter, cancellationToken);
    }

    /// <inheritdoc />
    public string Render(ScanResult result, ReportFormat format) => _runner.Render(result, format);

    /// <inheritdoc />
    public string Render(BaselineDiff diff, ReportFormat format) => _runner.Render(diff, format);

    /// <inheritdoc />
    public Task<ScanResult> LoadAsync(string path, CancellationToken cancellationToken) =>
        BaselineStore.LoadAsync(path, cancellationToken);

    /// <inheritdoc />
    public Task SaveAsync(ScanResult result, string path, CancellationToken cancellationToken) =>
        BaselineStore.SaveAsync(result, path, cancellationToken);
}
