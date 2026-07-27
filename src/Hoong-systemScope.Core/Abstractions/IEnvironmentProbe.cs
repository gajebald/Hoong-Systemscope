using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Core.Abstractions;

/// <summary>A user profile present on the machine.</summary>
/// <param name="Sid">Security identifier in string form, used as the HKEY_USERS subkey name.</param>
/// <param name="UserName">Resolved account name, when it could be determined.</param>
/// <param name="ProfilePath">Path of the user profile directory, when known.</param>
/// <param name="IsHiveLoaded">True when the user's registry hive is currently loaded.</param>
public sealed record UserProfile(string Sid, string? UserName, string? ProfilePath, bool IsHiveLoaded);

/// <summary>Machine and environment facts needed by the collectors.</summary>
public interface IEnvironmentProbe
{
    /// <summary>Describes the machine the scan runs on.</summary>
    MachineInfo GetMachineInfo();

    /// <summary>Expands <c>%VARIABLE%</c> references using the current process environment.</summary>
    string ExpandEnvironmentVariables(string value);

    /// <summary>Windows directory, for example <c>C:\Windows</c>.</summary>
    string WindowsDirectory { get; }

    /// <summary>System directory, for example <c>C:\Windows\System32</c>.</summary>
    string SystemDirectory { get; }

    /// <summary>32 bit system directory on a 64 bit machine, for example <c>C:\Windows\SysWOW64</c>.</summary>
    string? SystemDirectoryWow64 { get; }

    /// <summary>Startup folder of the current user.</summary>
    string? CurrentUserStartupFolder { get; }

    /// <summary>Startup folder shared by all users.</summary>
    string? CommonStartupFolder { get; }

    /// <summary>Temporary directories that are considered unusual autostart locations.</summary>
    IReadOnlyList<string> TemporaryDirectories { get; }

    /// <summary>Path of the <c>hosts</c> file.</summary>
    string HostsFilePath { get; }

    /// <summary>
    /// Enumerates user profiles. Profiles whose hive is not loaded are reported
    /// with <see cref="UserProfile.IsHiveLoaded"/> set to false and are never
    /// mounted, because mounting would modify the system.
    /// </summary>
    IReadOnlyList<UserProfile> GetUserProfiles();
}
