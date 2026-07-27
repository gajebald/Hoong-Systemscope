namespace HoongSystemScope.Core.Abstractions;

/// <summary>Basic facts about a file, gathered without opening it for writing.</summary>
/// <param name="Exists">Whether the file exists.</param>
/// <param name="SizeBytes">Size in bytes, or null when unknown.</param>
/// <param name="CreatedUtc">Creation timestamp, or null when unknown.</param>
/// <param name="ModifiedUtc">Last write timestamp, or null when unknown.</param>
public sealed record FileStat(bool Exists, long? SizeBytes, DateTimeOffset? CreatedUtc, DateTimeOffset? ModifiedUtc)
{
    /// <summary>Shared instance for a file that does not exist.</summary>
    public static FileStat Missing { get; } = new(false, null, null, null);
}

/// <summary>
/// Read-only file system access.
/// </summary>
/// <remarks>
/// Every implementation must open files with read access only and must share
/// them for reading, writing and deletion, so that inspecting a file never
/// blocks the process that owns it.
/// </remarks>
public interface IFileSystemProbe
{
    /// <summary>True when the given path points at an existing file.</summary>
    bool FileExists(string path);

    /// <summary>True when the given path points at an existing directory.</summary>
    bool DirectoryExists(string path);

    /// <summary>Returns size and timestamps, or <see cref="FileStat.Missing"/>.</summary>
    FileStat Stat(string path);

    /// <summary>Enumerates files in a directory. Returns an empty sequence when it is not readable.</summary>
    IEnumerable<string> EnumerateFiles(string directory, string searchPattern = "*", bool recursive = false);

    /// <summary>Opens a file for reading, or returns null when it cannot be opened.</summary>
    Stream? OpenRead(string path);

    /// <summary>Reads all text of a file, or returns null when it cannot be read.</summary>
    string? ReadAllText(string path);

    /// <summary>
    /// True when a non-administrative user can write into the given directory.
    /// Used by the risk engine: a binary started by SYSTEM out of a directory
    /// that ordinary users can write to is a privilege escalation path.
    /// </summary>
    bool IsDirectoryWritableByStandardUsers(string directory);
}
