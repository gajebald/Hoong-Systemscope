using System.Runtime.Versioning;
using System.Security.Principal;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Windows;

/// <summary>Machine and environment facts read from the running system.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEnvironmentProbe : IEnvironmentProbe
{
    private const string ProfileListPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private readonly IRegistryReader _registry;

    /// <summary>Creates a probe over the given registry reader.</summary>
    public WindowsEnvironmentProbe(IRegistryReader registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
    }

    /// <inheritdoc />
    public string WindowsDirectory { get; } =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    /// <inheritdoc />
    public string SystemDirectory { get; } = Environment.SystemDirectory;

    /// <inheritdoc />
    public string? SystemDirectoryWow64 { get; } =
        Environment.Is64BitOperatingSystem
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
            : null;

    /// <inheritdoc />
    public string? CurrentUserStartupFolder { get; } =
        NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.Startup));

    /// <inheritdoc />
    public string? CommonStartupFolder { get; } =
        NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

    /// <inheritdoc />
    public IReadOnlyList<string> TemporaryDirectories { get; } =
    [
        Path.GetTempPath().TrimEnd('\\'),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
    ];

    /// <inheritdoc />
    public string HostsFilePath { get; } =
        Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");

    /// <inheritdoc />
    public MachineInfo GetMachineInfo() => new()
    {
        MachineName = Environment.MachineName,
        OperatingSystem = Environment.OSVersion.VersionString,
        Architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
        UserName = $@"{Environment.UserDomainName}\{Environment.UserName}",
        IsElevated = IsElevated(),
        Is64BitOperatingSystem = Environment.Is64BitOperatingSystem,
    };

    /// <inheritdoc />
    public string ExpandEnvironmentVariables(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Environment.ExpandEnvironmentVariables(value);
    }

    /// <inheritdoc />
    public IReadOnlyList<UserProfile> GetUserProfiles()
    {
        var profiles = new List<UserProfile>();

        using var profileList = _registry.OpenKey(RegistryHiveKind.LocalMachine, ProfileListPath);
        if (profileList is null)
        {
            return profiles;
        }

        // A hive counts as loaded when the SID appears under HKEY_USERS.
        // Hoong-systemScope never mounts one that is not, because loading a
        // hive writes to the machine.
        var loadedSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var users = _registry.OpenKey(RegistryHiveKind.Users, string.Empty))
        {
            if (users is not null)
            {
                foreach (var sid in users.GetSubKeyNames())
                {
                    loadedSids.Add(sid);
                }
            }
        }

        foreach (var sid in profileList.GetSubKeyNames())
        {
            using var profile = profileList.OpenSubKey(sid);
            var profilePath = profile?.GetValue("ProfileImagePath")?.AsString();

            profiles.Add(new UserProfile(
                sid,
                ResolveAccountName(sid),
                profilePath,
                loadedSids.Contains(sid)));
        }

        return profiles;
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>
    /// Translates a SID to an account name. Failure is expected for deleted or
    /// remote accounts and simply leaves the name unknown.
    /// </summary>
    private static string? ResolveAccountName(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch (Exception ex) when (ex is ArgumentException or IdentityNotMappedException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
