using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export;

/// <summary>Loads and saves scan results used as baselines.</summary>
/// <remarks>
/// This is the one place in the inspecting half of the tool that writes to
/// disk, and it only ever writes where the user pointed it. It never touches
/// the areas it scanned.
/// </remarks>
public sealed class BaselineStore
{
    /// <summary>Reads a baseline from disk.</summary>
    /// <exception cref="FileNotFoundException">The file does not exist.</exception>
    /// <exception cref="InvalidDataException">The file is not a readable scan result.</exception>
    public static async Task<ScanResult> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"No baseline was found at '{path}'.", path);
        }

        var json = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        return ScanJson.Deserialize(json);
    }

    /// <summary>Writes a scan result to disk so it can serve as a baseline later.</summary>
    public static async Task SaveAsync(ScanResult result, string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(path, ScanJson.Serialize(result), cancellationToken).ConfigureAwait(false);
    }
}
