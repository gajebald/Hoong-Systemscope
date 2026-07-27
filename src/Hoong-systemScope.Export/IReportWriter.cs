using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export;

/// <summary>Renders a scan result or a baseline comparison into text.</summary>
/// <remarks>
/// Writers return a string rather than touching the file system. Deciding
/// where output goes belongs to the command line layer, and keeping the
/// writers pure makes their output directly assertable in tests.
/// </remarks>
public interface IReportWriter
{
    /// <summary>The format this writer produces.</summary>
    ReportFormat Format { get; }

    /// <summary>Renders a scan result.</summary>
    string Write(ScanResult result);

    /// <summary>Renders a baseline comparison.</summary>
    string Write(BaselineDiff diff);
}
