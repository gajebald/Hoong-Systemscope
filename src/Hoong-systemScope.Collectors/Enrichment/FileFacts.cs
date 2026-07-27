using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Enrichment;

/// <summary>Everything that can be learned about a file on disk.</summary>
/// <param name="Exists">Whether the file exists.</param>
/// <param name="Metadata">Version resource fields.</param>
/// <param name="Sha256">SHA-256, when it was computed.</param>
/// <param name="Signature">Authenticode result.</param>
public sealed record FileFacts(
    bool Exists,
    FileMetadata Metadata,
    string? Sha256,
    SignatureInfo Signature)
{
    /// <summary>Facts for a path that does not exist.</summary>
    public static FileFacts Missing { get; } = new(
        false,
        FileMetadata.Empty,
        null,
        new SignatureInfo { Status = SignatureStatus.FileNotFound });
}
