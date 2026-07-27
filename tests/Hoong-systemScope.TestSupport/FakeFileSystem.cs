using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.TestSupport;

/// <summary>An in-memory file system exposing only the read operations the tool needs.</summary>
public sealed class FakeFileSystem : IFileSystemProbe
{
    private readonly Dictionary<string, string> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _directories = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _userWritableDirectories = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Registers a file with optional content.</summary>
    public FakeFileSystem AddFile(string path, string content = "")
    {
        _files[Normalize(path)] = content;

        var directory = GetDirectoryName(Normalize(path));
        while (directory is not null)
        {
            _directories.Add(directory);
            directory = GetDirectoryName(directory);
        }

        return this;
    }

    /// <summary>Registers an empty directory.</summary>
    public FakeFileSystem AddDirectory(string path)
    {
        _directories.Add(Normalize(path));
        return this;
    }

    /// <summary>Marks a directory as writable by standard users.</summary>
    public FakeFileSystem MarkUserWritable(string path)
    {
        _userWritableDirectories.Add(Normalize(path));
        return _directories.Add(Normalize(path)) ? this : this;
    }

    public bool FileExists(string path) => _files.ContainsKey(Normalize(path));

    public bool DirectoryExists(string path) => _directories.Contains(Normalize(path));

    public FileStat Stat(string path) =>
        _files.TryGetValue(Normalize(path), out var content)
            ? new FileStat(true, content.Length, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch)
            : FileStat.Missing;

    public IEnumerable<string> EnumerateFiles(string directory, string searchPattern = "*", bool recursive = false)
    {
        var normalized = Normalize(directory);
        if (!_directories.Contains(normalized))
        {
            yield break;
        }

        var prefix = normalized + "\\";
        foreach (var path in _files.Keys.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!recursive && path[prefix.Length..].Contains('\\', StringComparison.Ordinal))
            {
                continue;
            }

            if (searchPattern is not "*" && !MatchesPattern(path, searchPattern))
            {
                continue;
            }

            yield return path;
        }
    }

    public Stream? OpenRead(string path) =>
        _files.TryGetValue(Normalize(path), out var content)
            ? new MemoryStream(System.Text.Encoding.UTF8.GetBytes(content), writable: false)
            : null;

    public string? ReadAllText(string path) => _files.TryGetValue(Normalize(path), out var content) ? content : null;

    public bool IsDirectoryWritableByStandardUsers(string directory) =>
        _userWritableDirectories.Contains(Normalize(directory));

    private static bool MatchesPattern(string path, string searchPattern)
    {
        if (!searchPattern.StartsWith('*'))
        {
            return true;
        }

        var suffix = searchPattern[1..];
        return path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path) => path.Trim().Replace('/', '\\').TrimEnd('\\');

    private static string? GetDirectoryName(string path)
    {
        var index = path.LastIndexOf('\\');
        return index <= 2 ? null : path[..index];
    }
}
