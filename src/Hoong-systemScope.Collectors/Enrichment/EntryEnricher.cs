using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Enrichment;

/// <summary>
/// Fills the file-derived fields of an entry after its collector produced it.
/// </summary>
/// <remarks>
/// Collectors deliberately stop at "here is a path". Keeping hashing and
/// signature verification out of them means a collector stays a small, testable
/// piece of registry or API traversal, and it means the expensive work happens
/// once per file rather than once per mention of that file.
/// </remarks>
public sealed class EntryEnricher
{
    private readonly FileFactsCache _cache;

    /// <summary>Creates an enricher over the given cache.</summary>
    public EntryEnricher(FileFactsCache cache)
    {
        ArgumentNullException.ThrowIfNull(cache);
        _cache = cache;
    }

    /// <summary>Returns a copy of the entry with the file facts filled in.</summary>
    public async Task<ScanEntry> EnrichAsync(ScanEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        // For a rundll32 entry the executable is a Microsoft binary and tells
        // us nothing. Inspect the library it loads instead.
        var target = entry.Metadata.TryGetValue(MetadataKeys.Rundll32Target, out var dll) && dll is { Length: > 0 }
            ? dll
            : entry.ExecutablePath;

        if (string.IsNullOrWhiteSpace(target))
        {
            return entry;
        }

        var facts = await _cache.GetAsync(target, cancellationToken).ConfigureAwait(false);

        return entry with
        {
            FileExists = facts.Exists,
            Publisher = facts.Metadata.Publisher ?? entry.Publisher,
            ProductName = facts.Metadata.ProductName ?? entry.ProductName,
            FileDescription = facts.Metadata.FileDescription ?? entry.FileDescription,
            FileVersion = facts.Metadata.FileVersion ?? entry.FileVersion,
            Sha256 = facts.Sha256,
            Signature = facts.Signature,
            SignatureStatus = facts.Signature.Status,
        };
    }
}
