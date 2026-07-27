using HoongSystemScope.Core.Models;
using HoongSystemScope.ViewModels;

namespace HoongSystemScope.ViewModels.Tests;

public sealed class MainViewModelTests
{
    private static (MainViewModel ViewModel, FakeScanService Service) CreateSubject(ScanResult? result = null)
    {
        var service = new FakeScanService();

        if (result is not null)
        {
            service.Result = result;
        }

        return (new MainViewModel(service), service);
    }

    [Fact]
    public async Task Scanning_publishes_the_findings()
    {
        var (viewModel, _) = CreateSubject(ScanBuilder.Result(
        [
            ScanBuilder.Entry(name: "One"),
            ScanBuilder.Entry(name: "Two", category: ScanCategory.Service),
        ]));

        await viewModel.RunScanAsync();

        Assert.Equal(2, viewModel.TotalCount);
        Assert.Equal(2, viewModel.VisibleCount);
        Assert.Contains(viewModel.Entries, e => e.Name == "One");
        Assert.False(viewModel.IsScanning);
    }

    [Fact]
    public async Task The_status_line_says_the_machine_is_not_being_changed()
    {
        // The promise the whole tool rests on should be visible while it works,
        // not only in a readme.
        var (viewModel, service) = CreateSubject();
        service.Gate = new TaskCompletionSource();

        var scan = viewModel.RunScanAsync();
        var messageWhileRunning = viewModel.StatusMessage;

        service.Gate.SetResult();
        await scan;

        Assert.Contains("does not modify the machine", messageWhileRunning, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Progress_is_reported_as_a_fraction()
    {
        var (viewModel, service) = CreateSubject();
        service.ProgressUpdates.Add(new ScanProgressUpdate("services", 3, 12));

        var seen = new List<double>();
        viewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.ProgressFraction))
            {
                seen.Add(viewModel.ProgressFraction);
            }
        };

        await viewModel.RunScanAsync();

        Assert.Contains(0.25, seen);
    }

    [Fact]
    public async Task A_second_scan_cannot_start_while_one_is_running()
    {
        // Double-clicking the button must not launch two scans.
        var (viewModel, service) = CreateSubject();
        service.Gate = new TaskCompletionSource();

        var first = viewModel.ScanCommand.ExecuteAsync();

        Assert.False(viewModel.ScanCommand.CanExecute(null));

        var second = viewModel.ScanCommand.ExecuteAsync();

        service.Gate.SetResult();
        await Task.WhenAll(first, second);

        Assert.Equal(1, service.ScanCount);
    }

    [Fact]
    public async Task Cancelling_leaves_the_window_usable()
    {
        var (viewModel, service) = CreateSubject();
        service.Gate = new TaskCompletionSource();

        var scan = viewModel.RunScanAsync();
        viewModel.Cancel();
        await scan;

        Assert.False(viewModel.IsScanning);
        Assert.Contains("cancelled", viewModel.StatusMessage, StringComparison.OrdinalIgnoreCase);
        Assert.True(viewModel.ScanCommand.CanExecute(null));
    }

    [Fact]
    public async Task A_failed_scan_reports_the_reason_instead_of_crashing()
    {
        var (viewModel, service) = CreateSubject();
        service.Failure = new InvalidOperationException("registry unavailable");

        await viewModel.RunScanAsync();

        Assert.Contains("registry unavailable", viewModel.StatusMessage, StringComparison.Ordinal);
        Assert.False(viewModel.IsScanning);
    }

    [Fact]
    public async Task Coverage_gaps_are_surfaced_with_the_worst_first()
    {
        var (viewModel, _) = CreateSubject(ScanBuilder.Result(
            entries: [ScanBuilder.Entry()],
            errors:
            [
                new ScanError { CollectorId = "a", Severity = ScanErrorSeverity.Information, Message = "skipped" },
                new ScanError { CollectorId = "b", Severity = ScanErrorSeverity.Error, Message = "failed" },
            ]));

        await viewModel.RunScanAsync();

        Assert.Equal(2, viewModel.CoverageGaps.Count);
        Assert.Equal(ScanErrorSeverity.Error, viewModel.CoverageGaps[0].Severity);
    }

    [Fact]
    public async Task An_unelevated_scan_is_marked_as_limited()
    {
        // The user has to be able to tell an empty result from an unseen one.
        var (viewModel, _) = CreateSubject(ScanBuilder.Result(isElevated: false));

        await viewModel.RunScanAsync();

        Assert.True(viewModel.IsCoverageLimited);
    }

    [Fact]
    public async Task Filtering_narrows_the_visible_rows_without_losing_the_rest()
    {
        var (viewModel, _) = CreateSubject(ScanBuilder.Result(
        [
            ScanBuilder.Entry(name: "Quiet", riskLevel: RiskLevel.Informational),
            ScanBuilder.Entry(name: "Loud", riskLevel: RiskLevel.High, location: @"HKLM\Other"),
        ]));

        await viewModel.RunScanAsync();
        viewModel.MinimumRiskLevel = RiskLevel.Medium;

        Assert.Equal(1, viewModel.VisibleCount);
        Assert.Equal(2, viewModel.TotalCount);
        Assert.Equal("Loud", viewModel.Entries[0].Name);

        viewModel.ClearFilterCommand.Execute(null);

        Assert.Equal(2, viewModel.VisibleCount);
    }

    [Fact]
    public async Task The_selection_survives_a_filter_that_still_includes_it()
    {
        var (viewModel, _) = CreateSubject(ScanBuilder.Result(
        [
            ScanBuilder.Entry(name: "Loud", riskLevel: RiskLevel.High),
            ScanBuilder.Entry(name: "Quiet", location: @"HKLM\Other"),
        ]));

        await viewModel.RunScanAsync();
        viewModel.SelectedEntry = viewModel.Entries.Single(e => e.Name == "Loud");

        viewModel.SearchText = "loud";

        Assert.NotNull(viewModel.SelectedEntry);
        Assert.Equal("Loud", viewModel.SelectedEntry.Name);
    }

    [Fact]
    public async Task The_selection_is_cleared_when_the_filter_excludes_it()
    {
        var (viewModel, _) = CreateSubject(ScanBuilder.Result(
        [
            ScanBuilder.Entry(name: "Loud", riskLevel: RiskLevel.High),
            ScanBuilder.Entry(name: "Quiet", location: @"HKLM\Other"),
        ]));

        await viewModel.RunScanAsync();
        viewModel.SelectedEntry = viewModel.Entries.Single(e => e.Name == "Quiet");

        viewModel.MinimumRiskLevel = RiskLevel.High;

        // A detail pane still showing a row that is no longer in the grid would
        // misrepresent what the user is looking at.
        Assert.Null(viewModel.SelectedEntry);
    }

    [Fact]
    public async Task Comparing_against_a_baseline_summarises_the_differences()
    {
        var baseline = ScanBuilder.Result([ScanBuilder.Entry(name: "Old")]);
        var current = ScanBuilder.Result([ScanBuilder.Entry(name: "New")]);

        var service = new FakeScanService { Result = current };
        service.WithSavedScan("baseline.json", baseline);

        var viewModel = new MainViewModel(service);
        await viewModel.RunScanAsync();
        await viewModel.CompareWithBaselineAsync("baseline.json");

        Assert.True(viewModel.HasDiff);
        Assert.Contains("1 added", viewModel.DiffCaption, StringComparison.Ordinal);
        Assert.Contains("1 removed", viewModel.DiffCaption, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Comparing_before_scanning_says_so_rather_than_failing()
    {
        var service = new FakeScanService();
        service.WithSavedScan("baseline.json", ScanBuilder.Result());

        var viewModel = new MainViewModel(service);
        await viewModel.CompareWithBaselineAsync("baseline.json");

        Assert.False(viewModel.HasDiff);
        Assert.Contains("before comparing", viewModel.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Exporting_writes_the_comparison_when_one_is_on_screen()
    {
        // What the user sees is what they get.
        var service = new FakeScanService { Result = ScanBuilder.Result() };
        service.WithSavedScan("baseline.json", ScanBuilder.Result([ScanBuilder.Entry(name: "Old")]));

        var viewModel = new MainViewModel(service);
        await viewModel.RunScanAsync();
        await viewModel.CompareWithBaselineAsync("baseline.json");

        var path = Path.Combine(Path.GetTempPath(), $"hoong-vm-{Guid.NewGuid():N}.txt");

        try
        {
            await viewModel.ExportAsync(path, ReportFormat.Text);

            Assert.Equal("rendered-diff-Text", await File.ReadAllTextAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Exporting_writes_the_scan_when_no_comparison_is_shown()
    {
        var (viewModel, _) = CreateSubject();
        await viewModel.RunScanAsync();

        var path = Path.Combine(Path.GetTempPath(), $"hoong-vm-{Guid.NewGuid():N}.json");

        try
        {
            await viewModel.ExportAsync(path, ReportFormat.Json);

            Assert.Equal("rendered-scan-Json", await File.ReadAllTextAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Exporting_before_scanning_says_so_rather_than_writing_an_empty_file()
    {
        var (viewModel, _) = CreateSubject();
        var path = Path.Combine(Path.GetTempPath(), $"hoong-vm-{Guid.NewGuid():N}.json");

        await viewModel.ExportAsync(path, ReportFormat.Json);

        Assert.False(File.Exists(path));
        Assert.Contains("nothing to export", viewModel.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_saved_scan_can_be_reopened()
    {
        var (viewModel, service) = CreateSubject();
        await viewModel.RunScanAsync();
        await viewModel.SaveAsync("saved.json");

        var reopened = new MainViewModel(service);
        await reopened.OpenAsync("saved.json");

        Assert.Equal(viewModel.TotalCount, reopened.TotalCount);
    }

    [Fact]
    public void The_view_model_offers_no_way_to_change_the_inspected_system()
    {
        // The read-only promise has to hold at the presentation layer too. If a
        // "fix", "delete" or "disable" command is ever added, this fails.
        var forbidden = new[] { "delete", "remove", "disable", "kill", "terminate", "quarantine", "fix", "repair" };

        var members = typeof(MainViewModel)
            .GetMembers()
            .Concat(typeof(IScanService).GetMembers())
            .Select(m => m.Name)

            // Skip compiler-generated accessors; "remove_PropertyChanged" is
            // an event accessor, not a capability.
            .Where(name => !name.StartsWith("add_", StringComparison.Ordinal))
            .Where(name => !name.StartsWith("remove_", StringComparison.Ordinal))
            .Where(name => !name.StartsWith("get_", StringComparison.Ordinal))
            .Where(name => !name.StartsWith("set_", StringComparison.Ordinal))
            .ToArray();

        foreach (var member in members)
        {
            foreach (var word in forbidden)
            {
                Assert.False(
                    member.Contains(word, StringComparison.OrdinalIgnoreCase),
                    $"'{member}' looks like it changes the inspected system.");
            }
        }
    }
}
