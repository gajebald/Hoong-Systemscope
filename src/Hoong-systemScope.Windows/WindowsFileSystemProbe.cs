using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Windows;

/// <summary>
/// Read-only file system access.
/// </summary>
/// <remarks>
/// Files are opened with read access and shared for reading, writing and
/// deletion. Inspecting a file must never block the process that owns it, and a
/// diagnostic tool that locks a running program's image would be doing exactly
/// what it promises not to.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsFileSystemProbe : IFileSystemProbe
{
    /// <summary>Well-known groups that mean "any interactive user".</summary>
    private static readonly WellKnownSidType[] StandardUserGroups =
    [
        WellKnownSidType.WorldSid,
        WellKnownSidType.AuthenticatedUserSid,
        WellKnownSidType.BuiltinUsersSid,
        WellKnownSidType.InteractiveSid,
    ];

    /// <inheritdoc />
    public bool FileExists(string path) => !string.IsNullOrWhiteSpace(path) && File.Exists(path);

    /// <inheritdoc />
    public bool DirectoryExists(string path) => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path);

    /// <inheritdoc />
    public FileStat Stat(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists
                ? new FileStat(true, info.Length, info.CreationTimeUtc, info.LastWriteTimeUtc)
                : FileStat.Missing;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return FileStat.Missing;
        }
    }

    /// <inheritdoc />
    public IEnumerable<string> EnumerateFiles(string directory, string searchPattern = "*", bool recursive = false)
    {
        if (!DirectoryExists(directory))
        {
            return [];
        }

        try
        {
            return Directory.EnumerateFiles(
                directory,
                searchPattern,
                new EnumerationOptions
                {
                    RecurseSubdirectories = recursive,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint,
                });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <inheritdoc />
    public Stream? OpenRead(string path)
    {
        try
        {
            return new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    /// <inheritdoc />
    public string? ReadAllText(string path)
    {
        using var stream = OpenRead(path);
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <inheritdoc />
    public bool IsDirectoryWritableByStandardUsers(string directory)
    {
        if (!DirectoryExists(directory))
        {
            return false;
        }

        try
        {
            var security = new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Access);
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                {
                    continue;
                }

                if (!GrantsWrite(rule.FileSystemRights) || rule.IdentityReference is not SecurityIdentifier sid)
                {
                    continue;
                }

                if (StandardUserGroups.Any(group => sid.IsWellKnown(group)))
                {
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Unknown is reported as "not writable" so the risk engine errs
            // towards silence rather than towards a finding it cannot support.
            return false;
        }
    }

    private static bool GrantsWrite(FileSystemRights rights) =>
        rights.HasFlag(FileSystemRights.WriteData) ||
        rights.HasFlag(FileSystemRights.CreateFiles) ||
        rights.HasFlag(FileSystemRights.Modify) ||
        rights.HasFlag(FileSystemRights.FullControl) ||
        rights.HasFlag(FileSystemRights.TakeOwnership) ||
        rights.HasFlag(FileSystemRights.ChangePermissions);
}
