using System.Globalization;

namespace HoongSystemScope.Core.Text;

/// <summary>Where on disk a file lives, expressed in categories the risk rules care about.</summary>
[Flags]
public enum PathLocationKind
{
    /// <summary>None of the recognised locations.</summary>
    None = 0,

    /// <summary>Below the Windows directory.</summary>
    WindowsDirectory = 1 << 0,

    /// <summary>Below System32 or SysWOW64.</summary>
    SystemDirectory = 1 << 1,

    /// <summary>Below Program Files or Program Files (x86).</summary>
    ProgramFiles = 1 << 2,

    /// <summary>Below a user profile.</summary>
    UserProfile = 1 << 3,

    /// <summary>Below an AppData directory.</summary>
    AppData = 1 << 4,

    /// <summary>Below a temporary directory.</summary>
    Temporary = 1 << 5,

    /// <summary>Below a Downloads directory.</summary>
    Downloads = 1 << 6,

    /// <summary>Below the recycle bin.</summary>
    RecycleBin = 1 << 7,

    /// <summary>Directly in the root of a drive.</summary>
    DriveRoot = 1 << 8,

    /// <summary>On a UNC share.</summary>
    NetworkShare = 1 << 9,

    /// <summary>Below the WinSxS component store.</summary>
    ComponentStore = 1 << 10,
}

/// <summary>
/// Pure helpers for reasoning about Windows paths.
/// </summary>
/// <remarks>
/// Everything here is deliberately free of I/O and of any platform API so that
/// it can be exercised on any build agent.
/// </remarks>
public static class PathFacts
{
    private static readonly string[] ExecutableExtensions =
    [
        ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".dll", ".sys", ".ocx",
        ".cpl", ".msc", ".msi", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
        ".ps1", ".hta", ".jar", ".lnk",
    ];

    /// <summary>
    /// Extensions that are frequently used as the leading half of a double
    /// extension such as <c>invoice.pdf.exe</c>.
    /// </summary>
    private static readonly string[] DocumentExtensions =
    [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
        ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".zip", ".csv",
    ];

    /// <summary>Unicode characters that can visually reverse a file name.</summary>
    private static readonly char[] BidirectionalOverrides =
    [
        '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
        '\u2066', '\u2067', '\u2068', '\u2069',
    ];

    /// <summary>True when the extension of <paramref name="path"/> denotes something executable.</summary>
    public static bool HasExecutableExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var extension = GetExtension(path);
        return extension.Length > 0 && ExecutableExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Rewrites the native path forms that appear in the service database into
    /// ordinary Win32 paths.
    /// </summary>
    /// <param name="path">Raw path, for example <c>\??\C:\x.sys</c> or <c>\SystemRoot\System32\drivers\x.sys</c>.</param>
    /// <param name="windowsDirectory">Value used to replace <c>\SystemRoot</c>.</param>
    public static string? NormalizeNativePath(string? path, string windowsDirectory)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var value = path.Trim();

        // \??\C:\... and \\?\C:\... are the NT object manager forms.
        if (value.StartsWith(@"\??\", StringComparison.Ordinal) ||
            value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            value = Combine(windowsDirectory, value[@"\SystemRoot\".Length..]);
        }
        else if (value.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            value = Combine(windowsDirectory, value[@"SystemRoot\".Length..]);
        }
        else if (value.StartsWith(@"\Systemroot", StringComparison.OrdinalIgnoreCase))
        {
            value = Combine(windowsDirectory, value[@"\Systemroot".Length..].TrimStart('\\'));
        }
        else if (value.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) ||
                 value.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
        {
            // Driver image paths are frequently stored relative to %WinDir%.
            value = Combine(windowsDirectory, value);
        }

        return value.Length == 0 ? null : value;
    }

    /// <summary>Classifies a path into the locations the risk rules distinguish.</summary>
    /// <param name="path">Path to classify.</param>
    /// <param name="windowsDirectory">Windows directory of the scanned machine.</param>
    public static PathLocationKind Classify(string? path, string windowsDirectory)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return PathLocationKind.None;
        }

        var value = path.Replace('/', '\\').Trim();
        var kind = PathLocationKind.None;

        if (value.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return PathLocationKind.NetworkShare;
        }

        if (IsUnder(value, windowsDirectory))
        {
            kind |= PathLocationKind.WindowsDirectory;

            if (IsUnder(value, Combine(windowsDirectory, "System32")) ||
                IsUnder(value, Combine(windowsDirectory, "SysWOW64")))
            {
                kind |= PathLocationKind.SystemDirectory;
            }

            if (IsUnder(value, Combine(windowsDirectory, "WinSxS")))
            {
                kind |= PathLocationKind.ComponentStore;
            }

            if (ContainsSegment(value, "Temp"))
            {
                kind |= PathLocationKind.Temporary;
            }

            return kind;
        }

        if (ContainsSegment(value, "Program Files") || ContainsSegment(value, "Program Files (x86)"))
        {
            kind |= PathLocationKind.ProgramFiles;
        }

        if (ContainsSegment(value, "Users") || ContainsSegment(value, "Documents and Settings"))
        {
            kind |= PathLocationKind.UserProfile;
        }

        if (ContainsSegment(value, "AppData") || ContainsSegment(value, "Local Settings") ||
            ContainsSegment(value, "Application Data"))
        {
            kind |= PathLocationKind.AppData;
        }

        if (ContainsSegment(value, "Temp") || ContainsSegment(value, "Tmp") ||
            ContainsSegment(value, "INetCache") || ContainsSegment(value, "Temporary Internet Files"))
        {
            kind |= PathLocationKind.Temporary;
        }

        if (ContainsSegment(value, "Downloads"))
        {
            kind |= PathLocationKind.Downloads;
        }

        if (ContainsSegment(value, "$Recycle.Bin") || ContainsSegment(value, "RECYCLER"))
        {
            kind |= PathLocationKind.RecycleBin;
        }

        if (IsDriveRoot(value))
        {
            kind |= PathLocationKind.DriveRoot;
        }

        return kind;
    }

    /// <summary>True when the file sits directly in the root of a drive, for example <c>C:\evil.exe</c>.</summary>
    public static bool IsDriveRoot(string path)
    {
        if (path.Length < 4 || path[1] != ':')
        {
            return false;
        }

        var remainder = path[3..];
        return remainder.Length > 0 && !remainder.Contains('\\', StringComparison.Ordinal);
    }

    /// <summary>
    /// True when the file name carries a second, misleading extension such as
    /// <c>report.pdf.exe</c>.
    /// </summary>
    public static bool HasMisleadingDoubleExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var fileName = GetFileName(path);
        var lastDot = fileName.LastIndexOf('.');
        if (lastDot <= 0)
        {
            return false;
        }

        var last = fileName[lastDot..];
        if (!ExecutableExtensions.Contains(last, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        var stem = fileName[..lastDot];
        var previousDot = stem.LastIndexOf('.');
        if (previousDot <= 0)
        {
            return false;
        }

        var previous = stem[previousDot..];
        return DocumentExtensions.Contains(previous, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when the text contains a Unicode directional override. These can
    /// make <c>exe.txt</c> render as <c>txt.exe</c> and vice versa.
    /// </summary>
    public static bool ContainsBidirectionalOverride(string? text) =>
        !string.IsNullOrEmpty(text) && text.IndexOfAny(BidirectionalOverrides) >= 0;

    /// <summary>Extension of a path including the dot, or an empty string.</summary>
    public static string GetExtension(string path)
    {
        var fileName = GetFileName(path);
        var index = fileName.LastIndexOf('.');
        return index < 0 ? string.Empty : fileName[index..];
    }

    /// <summary>Last segment of a path, tolerant of both separators and of trailing separators.</summary>
    public static string GetFileName(string path)
    {
        var value = path.TrimEnd('\\', '/');
        var index = value.LastIndexOfAny(['\\', '/']);
        return index < 0 ? value : value[(index + 1)..];
    }

    /// <summary>
    /// Case-insensitive comparison key for a path: separators unified, trailing
    /// separators removed, upper-cased invariantly.
    /// </summary>
    public static string Normalize(string? path) =>
        string.IsNullOrWhiteSpace(path)
            ? string.Empty
            : path.Trim().Replace('/', '\\').TrimEnd('\\').ToUpperInvariant();

    /// <summary>True when <paramref name="path"/> lies inside <paramref name="directory"/>.</summary>
    public static bool IsUnder(string? path, string? directory)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var normalizedPath = Normalize(path);
        var normalizedDirectory = Normalize(directory);

        return normalizedPath.Length > normalizedDirectory.Length &&
               normalizedPath.StartsWith(normalizedDirectory, StringComparison.Ordinal) &&
               normalizedPath[normalizedDirectory.Length] == '\\';
    }

    private static bool ContainsSegment(string path, string segment)
    {
        var normalized = Normalize(path);
        var needle = segment.ToUpperInvariant();

        var index = normalized.IndexOf(needle, StringComparison.Ordinal);
        while (index >= 0)
        {
            var startsAtBoundary = index == 0 || normalized[index - 1] == '\\';
            var endIndex = index + needle.Length;
            var endsAtBoundary = endIndex == normalized.Length || normalized[endIndex] == '\\';

            if (startsAtBoundary && endsAtBoundary)
            {
                return true;
            }

            index = normalized.IndexOf(needle, index + 1, StringComparison.Ordinal);
        }

        return false;
    }

    private static string Combine(string left, string right) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{left.TrimEnd('\\')}\\{right.TrimStart('\\')}");
}
