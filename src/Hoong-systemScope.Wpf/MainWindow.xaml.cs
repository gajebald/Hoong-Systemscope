using System.Windows;
using HoongSystemScope.Core.Models;
using HoongSystemScope.ViewModels;
using Microsoft.Win32;

namespace HoongSystemScope.Wpf;

/// <summary>
/// The main window.
/// </summary>
/// <remarks>
/// Contains only what genuinely needs a window: the file dialogs, which cannot
/// live in a view model without dragging a UI framework into it. Everything the
/// dialogs then do is delegated straight back to <see cref="MainViewModel"/>,
/// which is covered by tests.
/// </remarks>
public partial class MainWindow : Window
{
    private const string ScanFilter = "Hoong-systemScope scan (*.json)|*.json|All files (*.*)|*.*";

    /// <summary>Creates the window.</summary>
    public MainWindow() => InitializeComponent();

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    private async void OnOpen(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        var dialog = new OpenFileDialog { Filter = ScanFilter, Title = "Open a saved scan" };

        if (dialog.ShowDialog(this) == true)
        {
            await RunGuardedAsync(() => viewModel.OpenAsync(dialog.FileName));
        }
    }

    private async void OnSave(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = ScanFilter,
            Title = "Save this scan as a baseline",
            FileName = "hoong-systemscope-baseline.json",
        };

        if (dialog.ShowDialog(this) == true)
        {
            await RunGuardedAsync(() => viewModel.SaveAsync(dialog.FileName));
        }
    }

    private async void OnCompare(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        var dialog = new OpenFileDialog { Filter = ScanFilter, Title = "Choose the earlier scan to compare against" };

        if (dialog.ShowDialog(this) == true)
        {
            await RunGuardedAsync(() => viewModel.CompareWithBaselineAsync(dialog.FileName));
        }
    }

    private async void OnExport(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } viewModel)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Export the report",
            Filter = "Text report (*.txt)|*.txt|JSON (*.json)|*.json|CSV (*.csv)|*.csv",
            FileName = "hoong-systemscope-report.txt",
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        // FilterIndex is one-based and follows the order declared above.
        var format = dialog.FilterIndex switch
        {
            2 => ReportFormat.Json,
            3 => ReportFormat.Csv,
            _ => ReportFormat.Text,
        };

        await RunGuardedAsync(() => viewModel.ExportAsync(dialog.FileName, format));
    }

    /// <summary>
    /// Runs a view model operation, turning a failure into a status message.
    /// A diagnostic tool that crashes on an unreadable file is worse than one
    /// that says the file is unreadable.
    /// </summary>
    private async Task RunGuardedAsync(Func<Task> operation)
    {
        try
        {
            await operation();
        }
#pragma warning disable CA1031 // Any failure here belongs in the status bar, not in a crash dialog.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            MessageBox.Show(
                this,
                ex.Message,
                "Hoong-systemScope",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }
}
