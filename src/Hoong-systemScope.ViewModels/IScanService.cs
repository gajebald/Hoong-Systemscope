using HoongSystemScope.Core.Models;

namespace HoongSystemScope.ViewModels;

/// <summary>How far a running scan has progressed.</summary>
/// <param name="Caption">Text to show, already formatted.</param>
/// <param name="Completed">Collectors finished so far.</param>
/// <param name="Total">Collectors that will run.</param>
public sealed record ScanProgressUpdate(string Caption, int Completed, int Total);

/// <summary>
/// The one thing the desktop front end needs from the scanning half of the
/// tool.
/// </summary>
/// <remarks>
/// <para>
/// Declared here, in the platform-neutral view model project, and implemented
/// in the Windows application layer. That inversion is what lets the entire
/// presentation logic be unit tested on a build agent that has no registry, no
/// WinTrust and no task scheduler.
/// </para>
/// <para>
/// Note what is absent: there is no method to remove, disable, quarantine or
/// terminate anything. The user interface cannot modify the inspected system
/// because the contract it talks to offers no way to.
/// </para>
/// </remarks>
public interface IScanService
{
    /// <summary>Runs a scan.</summary>
    Task<ScanResult> ScanAsync(
        ScanOptions options,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken cancellationToken);

    /// <summary>Renders a scan result in the given format.</summary>
    string Render(ScanResult result, ReportFormat format);

    /// <summary>Renders a baseline comparison in the given format.</summary>
    string Render(BaselineDiff diff, ReportFormat format);

    /// <summary>Loads a previously saved scan.</summary>
    Task<ScanResult> LoadAsync(string path, CancellationToken cancellationToken);

    /// <summary>Saves a scan so it can serve as a baseline later.</summary>
    Task SaveAsync(ScanResult result, string path, CancellationToken cancellationToken);
}
