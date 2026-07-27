namespace HoongSystemScope.Core.Models;

/// <summary>Outcome of an Authenticode verification for a single file.</summary>
public sealed record SignatureInfo
{
    /// <summary>Result of the verification.</summary>
    public required SignatureStatus Status { get; init; }

    /// <summary>Subject common name of the signing certificate, if any.</summary>
    public string? SubjectName { get; init; }

    /// <summary>Issuer common name of the signing certificate, if any.</summary>
    public string? IssuerName { get; init; }

    /// <summary>SHA-1 thumbprint of the signing certificate, if any.</summary>
    public string? Thumbprint { get; init; }

    /// <summary>True when the trust came from a security catalog rather than an embedded signature.</summary>
    public bool IsCatalogSigned { get; init; }

    /// <summary>Not-after date of the signing certificate, if known.</summary>
    public DateTimeOffset? CertificateNotAfterUtc { get; init; }

    /// <summary>Technical detail when <see cref="Status"/> is <see cref="SignatureStatus.Error"/>.</summary>
    public string? ErrorDetail { get; init; }

    /// <summary>Shared instance for files that were never checked.</summary>
    public static SignatureInfo NotChecked { get; } = new() { Status = SignatureStatus.NotChecked };

    /// <summary>True when the file carries trust from either an embedded signature or a catalog.</summary>
    public bool IsTrusted => Status is SignatureStatus.Valid or SignatureStatus.ValidCatalog;
}
