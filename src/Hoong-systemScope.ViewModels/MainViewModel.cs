using System.Collections.ObjectModel;
using System.Globalization;
using HoongSystemScope.Analysis;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.ViewModels;

/// <summary>
/// Drives the main window.
/// </summary>
/// <remarks>
/// <para>
/// Holds no reference to any UI framework, which is what allows the whole
/// interaction — scanning, filtering, selecting, comparing, exporting — to be
/// exercised in unit tests on a machine that has neither a registry nor a
/// display.
/// </para>
/// <para>
/// There is no command here that changes the inspected system, and there is no
/// way to add one without also changing <see cref="IScanService"/>, which
/// offers nothing but reading and rendering.
/// </para>
/// </remarks>
public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly IScanService _scanService;
    private readonly List<ScanEntryViewModel> _allEntries = [];

    private ScanResult? _result;
    private ScanResult? _baseline;
    private BaselineDiff? _diff;
    private ScanEntryViewModel? _selectedEntry;
    private EntryFilter _filter = EntryFilter.None;
    private string _statusMessage = "Ready. Nothing has been scanned yet.";
    private string? _progressCaption;
    private double _progressFraction;
    private bool _isScanning;
    private CancellationTokenSource? _cancellation;

    /// <summary>Creates the view model.</summary>
    public MainViewModel(IScanService scanService)
    {
        ArgumentNullException.ThrowIfNull(scanService);

        _scanService = scanService;

        ScanCommand = new AsyncRelayCommand(RunScanAsync, () => !IsScanning);
        CancelCommand = new RelayCommand(Cancel, () => IsScanning);
        ClearFilterCommand = new RelayCommand(() => Filter = EntryFilter.None, () => Filter.IsActive);
    }

    /// <summary>Findings after the current filter is applied.</summary>
    public ObservableCollection<ScanEntryViewModel> Entries { get; } = [];

    /// <summary>Areas the scan could not reach.</summary>
    public ObservableCollection<ScanError> CoverageGaps { get; } = [];

    /// <summary>Starts a scan.</summary>
    public AsyncRelayCommand ScanCommand { get; }

    /// <summary>Cancels a running scan.</summary>
    public RelayCommand CancelCommand { get; }

    /// <summary>Resets the filter.</summary>
    public RelayCommand ClearFilterCommand { get; }

    /// <summary>Options the next scan will use.</summary>
    public ScanOptions Options { get; set; } = ScanOptions.Default;

    /// <summary>The most recent scan, if any.</summary>
    public ScanResult? Result
    {
        get => _result;
        private set => SetProperty(ref _result, value);
    }

    /// <summary>The loaded baseline, if any.</summary>
    public ScanResult? Baseline
    {
        get => _baseline;
        private set => SetProperty(ref _baseline, value);
    }

    /// <summary>The comparison against the baseline, if one was made.</summary>
    public BaselineDiff? Diff
    {
        get => _diff;
        private set
        {
            if (SetProperty(ref _diff, value))
            {
                RaisePropertyChanged(nameof(HasDiff));
                RaisePropertyChanged(nameof(DiffCaption));
            }
        }
    }

    /// <summary>True when a comparison is available.</summary>
    public bool HasDiff => Diff is not null;

    /// <summary>One-line summary of the comparison.</summary>
    public string DiffCaption => Diff is null
        ? string.Empty
        : string.Create(
            CultureInfo.InvariantCulture,
            $"{Diff.Added.Count} added, {Diff.Removed.Count} removed, {Diff.Modified.Count} modified, {Diff.UnchangedCount} unchanged");

    /// <summary>The row the detail pane describes.</summary>
    public ScanEntryViewModel? SelectedEntry
    {
        get => _selectedEntry;
        set => SetProperty(ref _selectedEntry, value);
    }

    /// <summary>The active filter. Assigning re-applies it.</summary>
    public EntryFilter Filter
    {
        get => _filter;
        set
        {
            if (SetProperty(ref _filter, value))
            {
                ApplyFilter();
                ClearFilterCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Free-text search, surfaced separately so a text box can bind to it.</summary>
    public string? SearchText
    {
        get => Filter.SearchText;
        set => Filter = Filter with { SearchText = value };
    }

    /// <summary>Minimum risk level shown, surfaced separately for a combo box.</summary>
    public RiskLevel MinimumRiskLevel
    {
        get => Filter.MinimumRiskLevel;
        set => Filter = Filter with { MinimumRiskLevel = value };
    }

    /// <summary>Show only entries whose file is missing.</summary>
    public bool OnlyMissingFiles
    {
        get => Filter.OnlyMissingFiles;
        set => Filter = Filter with { OnlyMissingFiles = value };
    }

    /// <summary>Show only entries without a trusted signature.</summary>
    public bool OnlyUntrusted
    {
        get => Filter.OnlyUntrusted;
        set => Filter = Filter with { OnlyUntrusted = value };
    }

    /// <summary>Status line text.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    /// <summary>Progress line text while a scan runs.</summary>
    public string? ProgressCaption
    {
        get => _progressCaption;
        private set => SetProperty(ref _progressCaption, value);
    }

    /// <summary>Scan progress between 0 and 1.</summary>
    public double ProgressFraction
    {
        get => _progressFraction;
        private set => SetProperty(ref _progressFraction, value);
    }

    /// <summary>True while a scan runs.</summary>
    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (SetProperty(ref _isScanning, value))
            {
                ScanCommand.RaiseCanExecuteChanged();
                CancelCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Number of findings before filtering.</summary>
    public int TotalCount => _allEntries.Count;

    /// <summary>Number of findings currently shown.</summary>
    public int VisibleCount => Entries.Count;

    /// <summary>
    /// True when the scan ran without administrative rights, so the report is
    /// known to be incomplete.
    /// </summary>
    public bool IsCoverageLimited => Result is not null && !Result.Machine.IsElevated;

    /// <summary>Runs a scan and replaces the current findings.</summary>
    public async Task RunScanAsync()
    {
        _cancellation?.Dispose();
        _cancellation = new CancellationTokenSource();

        IsScanning = true;
        ProgressFraction = 0;
        ProgressCaption = "Starting…";
        StatusMessage = "Scanning. This does not modify the machine.";

        // Deliberately not System.Progress<T>: that posts to the captured
        // synchronization context, which makes progress arrive after the scan
        // has already finished under test. These are scalar properties, and
        // WPF's binding engine marshals property notifications to the UI
        // thread on its own, so reporting them inline is both safe and
        // deterministic.
        var progress = new SynchronousProgress<ScanProgressUpdate>(update =>
        {
            ProgressCaption = update.Caption;
            ProgressFraction = update.Total == 0 ? 0 : (double)update.Completed / update.Total;
        });

        try
        {
            // No ConfigureAwait(false) here or in the methods below: the
            // continuation calls Load, which mutates ObservableCollection.
            // WPF forbids that from any thread but the dispatcher.
            var result = await _scanService.ScanAsync(Options, progress, _cancellation.Token);

            Load(result);

            StatusMessage = result.IsPartial
                ? "Scan finished, but some collectors failed. See the coverage gaps."
                : "Scan finished.";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Scan cancelled.";
        }
#pragma warning disable CA1031 // A failed scan must leave the window usable, not crash it.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            StatusMessage = $"The scan failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            ProgressCaption = null;
            ProgressFraction = 0;
        }
    }

    /// <summary>Cancels a running scan. The partial result is kept.</summary>
    public void Cancel() => _cancellation?.Cancel();

    /// <summary>Releases the cancellation source of the last scan.</summary>
    public void Dispose()
    {
        _cancellation?.Dispose();
        _cancellation = null;
    }

    /// <summary>Takes a scan result as the current one.</summary>
    public void Load(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        Result = result;

        _allEntries.Clear();
        _allEntries.AddRange(result.Entries.Select(e => new ScanEntryViewModel(e)));

        CoverageGaps.Clear();
        foreach (var error in result.Errors.OrderByDescending(e => e.Severity))
        {
            CoverageGaps.Add(error);
        }

        ApplyFilter();

        RaisePropertyChanged(nameof(IsCoverageLimited));
    }

    /// <summary>Loads a saved scan from disk and shows it.</summary>
    public async Task OpenAsync(string path, CancellationToken cancellationToken = default)
    {
        var result = await _scanService.LoadAsync(path, cancellationToken);

        Load(result);
        Diff = null;
        StatusMessage = $"Loaded {result.Entries.Count} entries from the saved scan.";
    }

    /// <summary>Saves the current scan so it can serve as a baseline later.</summary>
    public async Task SaveAsync(string path, CancellationToken cancellationToken = default)
    {
        if (Result is null)
        {
            StatusMessage = "There is nothing to save yet.";
            return;
        }

        await _scanService.SaveAsync(Result, path, cancellationToken).ConfigureAwait(false);
        StatusMessage = $"Scan saved to {path}.";
    }

    /// <summary>Loads a baseline and compares the current scan against it.</summary>
    public async Task CompareWithBaselineAsync(string path, CancellationToken cancellationToken = default)
    {
        if (Result is null)
        {
            StatusMessage = "Run or open a scan before comparing.";
            return;
        }

        Baseline = await _scanService.LoadAsync(path, cancellationToken);
        Diff = new BaselineComparer().Compare(Baseline, Result);

        StatusMessage = Diff.IsEmpty
            ? "No differences from the baseline."
            : $"Compared against the baseline: {DiffCaption}.";
    }

    /// <summary>Writes the current view to a file in the given format.</summary>
    public async Task ExportAsync(string path, ReportFormat format, CancellationToken cancellationToken = default)
    {
        if (Result is null)
        {
            StatusMessage = "There is nothing to export yet.";
            return;
        }

        // Exporting while a comparison is on screen writes the comparison. What
        // the user sees is what they get.
        var content = Diff is not null
            ? _scanService.Render(Diff, format)
            : _scanService.Render(Result, format);

        await File.WriteAllTextAsync(path, content, cancellationToken).ConfigureAwait(false);
        StatusMessage = $"Report written to {path}.";
    }

    /// <summary>Re-runs the filter over the collected findings.</summary>
    private void ApplyFilter()
    {
        var previousId = SelectedEntry?.Id;

        Entries.Clear();
        foreach (var entry in Filter.Apply(_allEntries))
        {
            Entries.Add(entry);
        }

        // Keep the detail pane on the same entry when it survives the filter,
        // so tightening a filter does not silently move the selection.
        SelectedEntry = previousId is null
            ? null
            : Entries.FirstOrDefault(e => e.Id == previousId);

        RaisePropertyChanged(nameof(TotalCount));
        RaisePropertyChanged(nameof(VisibleCount));
    }
}
