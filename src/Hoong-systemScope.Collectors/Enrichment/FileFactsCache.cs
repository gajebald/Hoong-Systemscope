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
/// The cache stores a <see cref="Lazy{T}"/> over the in-flight
/// <see cref="Task{TResult}"/>, not the task itself.
/// <see cref="ConcurrentDictionary{TKey,TValue}.GetOrAdd(TKey, Func{TKey,TValue})"/>
/// may run its factory more than once for the same key under contention — it
/// only guarantees that one result is stored. Storing the task directly would
/// therefore still start several hashes for the same file and quietly undo the
/// deduplication; the lazy makes the factory itself run exactly once.
/// </para>
/// </remarks>
public sealed class FileFactsCache
{
    private readonly ConcurrentDictionary<string, Lazy<Task<FileFacts>>> _cache =
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

        var lazy = _cache.GetOrAdd(
            path,
            key => new Lazy<Task<FileFacts>>(
                () => InspectAsync(key, cancellationToken),
                LazyThreadSafetyMode.ExecutionAndPublication));

        return lazy.Value;
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
