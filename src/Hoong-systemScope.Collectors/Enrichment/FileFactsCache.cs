using System.Collections.Concurrent;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Security;

namespace HoongSystemScope.Collectors.Enrichment;

/// <summary>
/// Gathers hash, version resource and signature for a path, once.
/// </summary>
/// <remarks>
/// <para>
/// Hashing and Authenticode verification dominate the runtime of a scan, and a
/// typical machine points dozens of entries at the same handful of binaries:
/// <c>svchost.exe</c> alone backs most of the service list. Verifying it once
/// per service would turn a fifteen second scan into several minutes.
/// </para>
/// <para>
/// The cache stores the in-flight <see cref="Task{TResult}"/> rather than the
/// finished value, so concurrent collectors asking for the same path await one
/// computation instead of racing into several.
/// </para>
/// </remarks>
public sealed class FileFactsCache
{
    private readonly ConcurrentDictionary<string, Task<FileFacts>> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly IFileSystemProbe _fileSystem;
    private readonly IFileMetadataProvider _metadata;
    private readonly IHashProvider _hashes;
    private readonly ISignatureVerifier _signatures;
    private readonly ScanOptions _options;

    /// <summary>Creates a cache bound to one scan.</summary>
    public FileFactsCache(
        IFileSystemProbe fileSystem,
        IFileMetadataProvider metadata,
        IHashProvider hashes,
        ISignatureVerifier signatures,
        ScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(hashes);
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(options);

        _fileSystem = fileSystem;
        _metadata = metadata;
        _hashes = hashes;
        _signatures = signatures;
        _options = options;
    }

    /// <summary>Number of distinct paths inspected. Useful for diagnostics and tests.</summary>
    public int InspectedPathCount => _cache.Count;

    /// <summary>Returns the facts for a path, computing them at most once per scan.</summary>
    public Task<FileFacts> GetAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        return _cache.GetOrAdd(path, key => InspectAsync(key, cancellationToken));
    }

    private async Task<FileFacts> InspectAsync(string path, CancellationToken cancellationToken)
    {
        // Nothing on the deny list is ever opened, not even to read a version
        // resource.
        if (SensitiveLocations.IsDeniedPath(path) || !_fileSystem.FileExists(path))
        {
            return FileFacts.Missing;
        }

        var metadata = _metadata.Read(path);

        string? sha256 = null;
        if (_options.ComputeHashes)
        {
            sha256 = await _hashes
                .ComputeSha256Async(path, _options.MaxHashFileSizeBytes, cancellationToken)
                .ConfigureAwait(false);
        }

        var signature = _options.VerifySignatures
            ? await _signatures.VerifyAsync(path, cancellationToken).ConfigureAwait(false)
            : SignatureInfo.NotChecked;

        return new FileFacts(true, metadata, sha256, signature);
    }
}
