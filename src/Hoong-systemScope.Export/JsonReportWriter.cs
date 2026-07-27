using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export;

/// <summary>Writes the machine readable report.</summary>
public sealed class JsonReportWriter : IReportWriter
{
    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Json;

    /// <inheritdoc />
    public string Write(ScanResult result) => ScanJson.Serialize(result);

    /// <inheritdoc />
    public string Write(BaselineDiff diff) => ScanJson.Serialize(diff);
}
