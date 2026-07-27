using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Windows.Interop;

namespace HoongSystemScope.Windows;

/// <summary>
/// Verifies Authenticode signatures, embedded and catalog alike.
/// </summary>
/// <remarks>
/// <para>
/// The catalog half is what makes this useful. Most Windows system binaries
/// carry no embedded signature at all; their trust comes from a security
/// catalog under <c>System32\CatRoot</c>. A verifier that only calls
/// <c>WinVerifyTrust</c> with a file subject reports every one of them as
/// unsigned, and the resulting report is nothing but false positives.
/// </para>
/// <para>
/// So the file is checked twice: first as an embedded signature, and if that
/// comes back "no signature", the file's hash is looked up in the catalog
/// database and verified against the catalog that claims it.
/// </para>
/// <para>
/// Revocation checking is deliberately off. It would require network access,
/// and this tool is offline by design.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeSignatureVerifier : ISignatureVerifier
{
    private readonly IFileSystemProbe _fileSystem;

    /// <summary>Creates a verifier.</summary>
    public AuthenticodeSignatureVerifier(IFileSystemProbe fileSystem)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        _fileSystem = fileSystem;
    }

    /// <inheritdoc />
    public Task<SignatureInfo> VerifyAsync(string path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !_fileSystem.FileExists(path))
        {
            return Task.FromResult(new SignatureInfo { Status = SignatureStatus.FileNotFound });
        }

        cancellationToken.ThrowIfCancellationRequested();

        // WinVerifyTrust is synchronous and CPU bound. Running it on the thread
        // pool keeps the scan's parallelism useful without pretending the call
        // is asynchronous.
        return Task.Run(() => Verify(path), cancellationToken);
    }

    private SignatureInfo Verify(string path)
    {
        try
        {
            var embedded = VerifyEmbedded(path);

            // Only fall through to the catalog when the file genuinely has no
            // embedded signature. A broken embedded signature is a finding and
            // must not be masked by a catalog lookup.
            if (embedded.Status != SignatureStatus.Unsigned)
            {
                return embedded;
            }

            return VerifyCatalog(path) ?? embedded;
        }
#pragma warning disable CA1031 // Verification must degrade to a status, never take the scan down.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return new SignatureInfo
            {
                Status = SignatureStatus.Error,
                ErrorDetail = $"{ex.GetType().Name}: {ex.Message}",
            };
        }
    }

    private static SignatureInfo VerifyEmbedded(string path)
    {
        var filePathPointer = Marshal.StringToHGlobalUni(path);
        var fileInfoPointer = IntPtr.Zero;
        var dataPointer = IntPtr.Zero;

        try
        {
            var fileInfo = new NativeMethods.WintrustFileInfo
            {
                StructSize = (uint)Marshal.SizeOf<NativeMethods.WintrustFileInfo>(),
                FilePath = filePathPointer,
            };

            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WintrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var data = new NativeMethods.WintrustData
            {
                StructSize = (uint)Marshal.SizeOf<NativeMethods.WintrustData>(),
                UiChoice = NativeMethods.WtdUiNone,
                RevocationChecks = NativeMethods.WtdRevokeNone,
                UnionChoice = NativeMethods.WtdChoiceFile,
                UnionInfo = fileInfoPointer,
                StateAction = NativeMethods.WtdStateActionVerify,
                ProviderFlags = NativeMethods.WtdCacheOnlyUrlRetrieval,
            };

            dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WintrustData>());
            Marshal.StructureToPtr(data, dataPointer, false);

            var action = NativeMethods.GenericVerifyV2;
            var result = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, dataPointer);

            // The verifier holds state that has to be released explicitly.
            var written = Marshal.PtrToStructure<NativeMethods.WintrustData>(dataPointer);
            written.StateAction = NativeMethods.WtdStateActionClose;
            Marshal.StructureToPtr(written, dataPointer, false);
            NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, dataPointer);

            return Describe(result, path, isCatalog: false);
        }
        finally
        {
            if (dataPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(dataPointer);
            }

            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPointer);
            }

            Marshal.FreeHGlobal(filePathPointer);
        }
    }

    /// <summary>
    /// Looks the file's hash up in the catalog database and verifies the
    /// catalog that claims it. Returns null when no catalog covers the file.
    /// </summary>
    private SignatureInfo? VerifyCatalog(string path)
    {
        var catalogAdmin = IntPtr.Zero;
        var catalogContext = IntPtr.Zero;

        try
        {
            if (!NativeMethods.CryptCATAdminAcquireContext2(
                    out catalogAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            {
                return null;
            }

            using var stream = _fileSystem.OpenRead(path);
            if (stream is not FileStream fileStream)
            {
                return null;
            }

            var handle = fileStream.SafeFileHandle.DangerousGetHandle();

            uint hashLength = 0;
            NativeMethods.CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref hashLength, null, 0);

            if (hashLength == 0)
            {
                return null;
            }

            var hash = new byte[hashLength];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref hashLength, hash, 0))
            {
                return null;
            }

            catalogContext = NativeMethods.CryptCATAdminEnumCatalogFromHash(
                catalogAdmin, hash, hashLength, 0, IntPtr.Zero);

            if (catalogContext == IntPtr.Zero)
            {
                return null;
            }

            var info = new NativeMethods.CatalogInfo
            {
                StructSize = (uint)Marshal.SizeOf<NativeMethods.CatalogInfo>(),
                CatalogFile = string.Empty,
            };

            if (!NativeMethods.CryptCATCatalogInfoFromContext(catalogContext, ref info, 0))
            {
                return null;
            }

            var catalogPath = info.CatalogFile;
            if (string.IsNullOrWhiteSpace(catalogPath))
            {
                return null;
            }

            // The catalog file itself is signed. Verifying it is what actually
            // establishes trust; the hash lookup only says which one to check.
            var catalogTrust = VerifyEmbedded(catalogPath);

            return catalogTrust.Status == SignatureStatus.Valid
                ? catalogTrust with { Status = SignatureStatus.ValidCatalog, IsCatalogSigned = true }
                : catalogTrust with { IsCatalogSigned = true };
        }
#pragma warning disable CA1031 // A catalog lookup that fails simply means "no catalog", never a failed scan.
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
        finally
        {
            if (catalogContext != IntPtr.Zero && catalogAdmin != IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
            }

            if (catalogAdmin != IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseContext(catalogAdmin, 0);
            }
        }
    }

    private static SignatureInfo Describe(int result, string path, bool isCatalog)
    {
        var status = result switch
        {
            NativeMethods.TrustEOk => isCatalog ? SignatureStatus.ValidCatalog : SignatureStatus.Valid,
            NativeMethods.TrustENosignature => SignatureStatus.Unsigned,
            NativeMethods.TrustESubjectFormUnknown => SignatureStatus.Unsigned,
            NativeMethods.TrustEProviderUnknown => SignatureStatus.Unsigned,
            NativeMethods.TrustEBadDigest => SignatureStatus.Invalid,
            NativeMethods.TrustEExplicitDistrust => SignatureStatus.Revoked,
            NativeMethods.CertERevoked => SignatureStatus.Revoked,
            NativeMethods.TrustEUntrustedRoot => SignatureStatus.UntrustedRoot,
            NativeMethods.CertEChaining => SignatureStatus.UntrustedRoot,
            NativeMethods.CertEExpired => SignatureStatus.Expired,
            _ => SignatureStatus.Invalid,
        };

        if (status == SignatureStatus.Unsigned)
        {
            return new SignatureInfo { Status = status };
        }

        return ReadCertificate(path) is { } certificate
            ? certificate with { Status = status }
            : new SignatureInfo { Status = status };
    }

    /// <summary>
    /// Reads the signing certificate for display. Failure here downgrades the
    /// detail, never the verdict.
    /// </summary>
    private static SignatureInfo? ReadCertificate(string path)
    {
        try
        {
            // CreateFromSignedFile extracts the certificate the file was
            // actually signed with, which is what has to be reported. Loading
            // the file as a certificate would read something else entirely.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));

            return new SignatureInfo
            {
                Status = SignatureStatus.Valid,
                SubjectName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                IssuerName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
                Thumbprint = certificate.Thumbprint,
                CertificateNotAfterUtc = certificate.NotAfter.ToUniversalTime(),
            };
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
