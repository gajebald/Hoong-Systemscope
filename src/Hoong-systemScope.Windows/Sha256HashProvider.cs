using System.Security.Cryptography;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Windows;

/// <summary>Computes SHA-256 over a file without holding it open exclusively.</summary>
public sealed class Sha256HashProvider : IHashProvider
{
    private readonly IFileSystemProbe _fileSystem;

    /// <summary>Creates a provider that reads through the given probe.</summary>
    public Sha256HashProvider(IFileSystemProbe fileSystem)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        _fileSystem = fileSystem;
    }

    /// <inheritdoc />
    public async Task<string?> ComputeSha256Async(string path, long maxSizeBytes, CancellationToken cancellationToken)
    {
        var stat = _fileSystem.Stat(path);

        // A multi-gigabyte file would stall the scan for no diagnostic gain;
        // report no hash rather than block.
        if (!stat.Exists || (stat.SizeBytes is { } size && size > maxSizeBytes))
        {
            return null;
        }

        await using var stream = _fileSystem.OpenRead(path);
        if (stream is null)
        {
            return null;
        }

        try
        {
            var digest = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            return Convert.ToHexString(digest).ToLowerInvariant();
        }
        catch (IOException)
        {
            return null;
        }
    }
}
