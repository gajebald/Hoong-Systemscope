namespace HoongSystemScope.Core.Models;

/// <summary>Output formats supported by the exporters.</summary>
public enum ReportFormat
{
    /// <summary>Machine readable JSON. The only format that can be re-read as a baseline.</summary>
    Json = 0,

    /// <summary>Human readable text report.</summary>
    Text,

    /// <summary>Flat CSV, one row per entry.</summary>
    Csv,
}
