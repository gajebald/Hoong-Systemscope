namespace HoongSystemScope.Core.Models;

/// <summary>
/// Result of an Authenticode verification.
/// </summary>
/// <remarks>
/// <see cref="ValidCatalog"/> is a distinct value on purpose: the majority of
/// Windows system binaries carry no embedded signature and are instead covered
/// by a security catalog. Treating those as <see cref="Unsigned"/> would flood
/// the report with false positives.
/// </remarks>
public enum SignatureStatus
{
    /// <summary>Verification was not requested or not attempted.</summary>
    NotChecked = 0,

    /// <summary>No embedded signature and no catalog entry.</summary>
    Unsigned,

    /// <summary>Valid embedded Authenticode signature.</summary>
    Valid,

    /// <summary>Valid signature provided by a security catalog.</summary>
    ValidCatalog,

    /// <summary>Signature present but the file does not match it.</summary>
    Invalid,

    /// <summary>Signature expired and carries no valid counter signature.</summary>
    Expired,

    /// <summary>Chain terminates in a root that is not trusted on this machine.</summary>
    UntrustedRoot,

    /// <summary>Signing certificate was revoked.</summary>
    Revoked,

    /// <summary>The file to verify does not exist.</summary>
    FileNotFound,

    /// <summary>Verification failed for a technical reason.</summary>
    Error,
}
