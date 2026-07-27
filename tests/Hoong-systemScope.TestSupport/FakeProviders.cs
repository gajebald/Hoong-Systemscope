using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.TestSupport;

/// <summary>A clock that never moves, so scan output is byte-for-byte reproducible.</summary>
public sealed class FixedClock : ISystemClock
{
    public FixedClock(DateTimeOffset now) => UtcNow = now;

    /// <summary>A fixed instant used as the default across the test suite.</summary>
    public static FixedClock Default { get; } = new(new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero));

    public DateTimeOffset UtcNow { get; }
}

/// <summary>Returns preconfigured version resource fields per path.</summary>
public sealed class FakeFileMetadataProvider : IFileMetadataProvider
{
    private readonly Dictionary<string, FileMetadata> _metadata = new(StringComparer.OrdinalIgnoreCase);

    public FakeFileMetadataProvider Add(string path, FileMetadata metadata)
    {
        _metadata[path] = metadata;
        return this;
    }

    public FileMetadata Read(string path) =>
        _metadata.TryGetValue(path, out var metadata) ? metadata : FileMetadata.Empty;
}

/// <summary>Returns preconfigured hashes per path.</summary>
public sealed class FakeHashProvider : IHashProvider
{
    private readonly Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Number of times a hash was actually computed, used to prove deduplication works.</summary>
    public int ComputeCount { get; private set; }

    public FakeHashProvider Add(string path, string sha256)
    {
        _hashes[path] = sha256;
        return this;
    }

    public Task<string?> ComputeSha256Async(string path, long maxSizeBytes, CancellationToken cancellationToken)
    {
        ComputeCount++;
        return Task.FromResult(_hashes.TryGetValue(path, out var hash) ? hash : null);
    }
}

/// <summary>Returns preconfigured signature results per path.</summary>
public sealed class FakeSignatureVerifier : ISignatureVerifier
{
    private readonly Dictionary<string, SignatureInfo> _results = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Result used for paths that were not explicitly configured.</summary>
    public SignatureInfo Fallback { get; set; } = new() { Status = SignatureStatus.Unsigned };

    /// <summary>Number of times a verification was actually performed.</summary>
    public int VerifyCount { get; private set; }

    public FakeSignatureVerifier Add(string path, SignatureInfo info)
    {
        _results[path] = info;
        return this;
    }

    /// <summary>Convenience helper for the common "signed by Microsoft" case.</summary>
    public FakeSignatureVerifier AddMicrosoft(string path) => Add(path, new SignatureInfo
    {
        Status = SignatureStatus.Valid,
        SubjectName = "Microsoft Windows",
        IssuerName = "Microsoft Windows Production PCA 2011",
        Thumbprint = "0000000000000000000000000000000000000000",
    });

    public Task<SignatureInfo> VerifyAsync(string path, CancellationToken cancellationToken)
    {
        VerifyCount++;
        return Task.FromResult(_results.TryGetValue(path, out var info) ? info : Fallback);
    }
}

/// <summary>Returns a fixed list of services.</summary>
public sealed class FakeServiceCatalog : IServiceCatalog
{
    public List<ServiceRecord> Services { get; } = [];

    public IEnumerable<ServiceRecord> Enumerate(CancellationToken cancellationToken) => Services;
}

/// <summary>Returns a fixed list of scheduled tasks.</summary>
public sealed class FakeScheduledTaskProvider : IScheduledTaskProvider
{
    public List<ScheduledTaskRecord> Tasks { get; } = [];

    public IEnumerable<ScheduledTaskRecord> Enumerate(CancellationToken cancellationToken) => Tasks;
}

/// <summary>Returns a fixed list of processes.</summary>
public sealed class FakeProcessProvider : IProcessProvider
{
    public List<ProcessRecord> Processes { get; } = [];

    public IEnumerable<ProcessRecord> Enumerate(CancellationToken cancellationToken) => Processes;
}

/// <summary>Resolves shell links from a preconfigured table.</summary>
public sealed class FakeShortcutResolver : IShortcutResolver
{
    private readonly Dictionary<string, ShortcutTarget> _targets = new(StringComparer.OrdinalIgnoreCase);

    public FakeShortcutResolver Add(string shortcutPath, string? target, string? arguments = null)
    {
        _targets[shortcutPath] = new ShortcutTarget(target, arguments, null);
        return this;
    }

    public ShortcutTarget? Resolve(string shortcutPath) =>
        _targets.TryGetValue(shortcutPath, out var target) ? target : null;
}
