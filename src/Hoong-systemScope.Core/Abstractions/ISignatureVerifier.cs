using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Core.Abstractions;

/// <summary>Verifies Authenticode signatures.</summary>
public interface ISignatureVerifier
{
    /// <summary>
    /// Verifies a file. Implementations must consider security catalogs, not
    /// only embedded signatures, otherwise most Windows system binaries are
    /// misreported as unsigned.
    /// </summary>
    Task<SignatureInfo> VerifyAsync(string path, CancellationToken cancellationToken);
}
