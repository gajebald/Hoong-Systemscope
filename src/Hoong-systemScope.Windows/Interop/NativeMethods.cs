using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HoongSystemScope.Windows.Interop;

/// <summary>
/// The Win32 entry points Hoong-systemScope uses.
/// </summary>
/// <remarks>
/// Every declaration here reads. None of them creates, writes, deletes or
/// launches anything, and the architecture test in Core.Tests fails the build
/// if one that does is added.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static partial class NativeMethods
{
    // WinVerifyTrust result codes, as returned rather than thrown.
    internal const int TrustEOk = 0;
    internal const int TrustENosignature = unchecked((int)0x800B0100);
    internal const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    internal const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    internal const int TrustEProviderUnknown = unchecked((int)0x800B0001);
    internal const int TrustEBadDigest = unchecked((int)0x80096010);
    internal const int TrustEUntrustedRoot = unchecked((int)0x800B0109);
    internal const int CertERevoked = unchecked((int)0x800B010C);
    internal const int CertEExpired = unchecked((int)0x800B0101);
    internal const int CertEChaining = unchecked((int)0x800B010A);

    internal const uint WtdUiNone = 2;
    internal const uint WtdRevokeNone = 0;
    internal const uint WtdChoiceFile = 1;
    internal const uint WtdStateActionVerify = 1;
    internal const uint WtdStateActionClose = 2;

    // Keeps WinVerifyTrust from reaching out to a revocation endpoint. The
    // tool works offline by design.
    internal const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    /// <summary>WINTRUST_ACTION_GENERIC_VERIFY_V2.</summary>
    internal static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [LibraryImport("wintrust.dll", SetLastError = false)]
    internal static partial int WinVerifyTrust(IntPtr window, ref Guid actionId, IntPtr data);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminAcquireContext2(
        out IntPtr catalogAdmin,
        IntPtr subsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? hashAlgorithm,
        IntPtr strongHashPolicy,
        uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr catalogAdmin,
        IntPtr file,
        ref uint hashLength,
        byte[]? hash,
        uint flags);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    internal static partial IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr catalogAdmin,
        byte[] hash,
        uint hashLength,
        uint flags,
        IntPtr previousCatalogInfo);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseCatalogContext(
        IntPtr catalogAdmin,
        IntPtr catalogContext,
        uint flags);

    // CatalogInfo carries a fixed-size inline character buffer, which the
    // LibraryImport generator does not marshal. Classic DllImport does.
    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATCatalogInfoFromContext(
        IntPtr catalogContext,
        ref CatalogInfo catalogInfo,
        uint flags);

    // The caller supplies the buffer, so a plain character array is both the
    // simplest marshalling and the one the analyzers prefer.
    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        char[] exeName,
        ref uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);

    internal const uint ProcessQueryLimitedInformation = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct WintrustFileInfo
    {
        internal uint StructSize;
        internal IntPtr FilePath;
        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WintrustData
    {
        internal uint StructSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr UnionInfo;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr Url;
        internal uint ProviderFlags;
        internal uint UiContext;
        internal IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CatalogInfo
    {
        internal uint StructSize;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string CatalogFile;
    }
}
