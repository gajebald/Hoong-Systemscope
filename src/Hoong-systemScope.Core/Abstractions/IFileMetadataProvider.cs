namespace HoongSystemScope.Core.Abstractions;

/// <summary>Version resource fields of a portable executable.</summary>
public sealed record FileMetadata
{
    /// <summary>Company name.</summary>
    public string? Publisher { get; init; }

    /// <summary>Product name.</summary>
    public string? ProductName { get; init; }

    /// <summary>File description.</summary>
    public string? FileDescription { get; init; }

    /// <summary>File version.</summary>
    public string? FileVersion { get; init; }

    /// <summary>Original file name recorded at build time.</summary>
    public string? OriginalFileName { get; init; }

    /// <summary>Shared instance for files without a readable version resource.</summary>
    public static FileMetadata Empty { get; } = new();

    /// <summary>True when no field carries a value.</summary>
    public bool IsEmpty =>
        Publisher is null && ProductName is null && FileDescription is null &&
        FileVersion is null && OriginalFileName is null;
}

/// <summary>Reads the version resource of a file.</summary>
public interface IFileMetadataProvider
{
    /// <summary>Reads the version resource, returning <see cref="FileMetadata.Empty"/> on failure.</summary>
    FileMetadata Read(string path);
}
