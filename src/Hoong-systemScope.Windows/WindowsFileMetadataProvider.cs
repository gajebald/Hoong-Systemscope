using System.Diagnostics;
using System.Runtime.Versioning;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Windows;

/// <summary>Reads the version resource of a portable executable.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFileMetadataProvider : IFileMetadataProvider
{
    /// <inheritdoc />
    public FileMetadata Read(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return FileMetadata.Empty;
        }

        try
        {
            // FileVersionInfo parses the resource; it never loads or runs the
            // image.
            var info = FileVersionInfo.GetVersionInfo(path);

            return new FileMetadata
            {
                Publisher = Clean(info.CompanyName),
                ProductName = Clean(info.ProductName),
                FileDescription = Clean(info.FileDescription),
                FileVersion = Clean(info.FileVersion),
                OriginalFileName = Clean(info.OriginalFilename),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return FileMetadata.Empty;
        }
    }

    private static string? Clean(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
