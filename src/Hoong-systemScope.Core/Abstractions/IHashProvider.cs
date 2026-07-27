namespace HoongSystemScope.Core.Abstractions;

/// <summary>Computes file hashes.</summary>
public interface IHashProvider
{
    /// <summary>
    /// Computes the lower case hexadecimal SHA-256 of a file, or returns null
    /// when the file cannot be read or exceeds <paramref name="maxSizeBytes"/>.
    /// </summary>
    Task<string?> ComputeSha256Async(string path, long maxSizeBytes, CancellationToken cancellationToken);
}
