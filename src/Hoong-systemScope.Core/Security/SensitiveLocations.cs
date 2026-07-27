namespace HoongSystemScope.Core.Security;

/// <summary>
/// Locations this tool must never read.
/// </summary>
/// <remarks>
/// Hoong-systemScope inspects persistence points, not secrets. Credential
/// stores, browser profiles and the LSA secrets contain nothing that helps
/// identify an autostart entry, and a diagnostic report is routinely shared
/// with strangers for help. The deny list is checked by the collectors before
/// any registry key or directory is opened, so a future collector cannot reach
/// into these areas by accident.
/// </remarks>
public static class SensitiveLocations
{
    private static readonly string[] DeniedRegistryPaths =
    [
        @"SAM",
        @"SECURITY",
        @"SYSTEM\CURRENTCONTROLSET\CONTROL\LSA\SECRETS",
        @"SECURITY\POLICY\SECRETS",
        @"SOFTWARE\MICROSOFT\CRYPTOGRAPHY\PROTECT",
        @"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON\DEFAULTPASSWORD",
        @"SOFTWARE\MICROSOFT\CREDENTIALS",
        @"SOFTWARE\MICROSOFT\VAULT",
        @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\CREDENTIALS",
    ];

    private static readonly string[] DeniedDirectorySegments =
    [
        "MICROSOFT\\CREDENTIALS",
        "MICROSOFT\\VAULT",
        "MICROSOFT\\PROTECT",
        "MICROSOFT\\CRYPTO",
        "GOOGLE\\CHROME\\USER DATA",
        "MICROSOFT\\EDGE\\USER DATA",
        "MOZILLA\\FIREFOX\\PROFILES",
        "BRAVESOFTWARE\\BRAVE-BROWSER\\USER DATA",
        "\\COOKIES",
        "\\LOGIN DATA",
    ];

    /// <summary>
    /// True when the given registry path must not be read.
    /// </summary>
    /// <param name="path">Path below a hive root, without the hive name.</param>
    public static bool IsDeniedRegistryPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Trim().Trim('\\').ToUpperInvariant();

        foreach (var denied in DeniedRegistryPaths)
        {
            if (normalized.Equals(denied, StringComparison.Ordinal) ||
                normalized.StartsWith(denied + "\\", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True when the given file system path must not be read.</summary>
    public static bool IsDeniedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Trim().Replace('/', '\\').ToUpperInvariant();

        foreach (var segment in DeniedDirectorySegments)
        {
            if (normalized.Contains(segment, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
