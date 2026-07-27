using System.Runtime.Versioning;
using HoongSystemScope.Core.Abstractions;
using Microsoft.Win32;
using CoreRegistryValueKind = HoongSystemScope.Core.Abstractions.RegistryValueKind;

namespace HoongSystemScope.Windows;

/// <summary>
/// Read-only registry access backed by <c>Microsoft.Win32</c>.
/// </summary>
/// <remarks>
/// Keys are opened with <see cref="RegistryKeyPermissionCheck.Default"/> and
/// without write rights. Combined with <see cref="IRegistryReader"/> having no
/// write member at all, there is no code path from this tool back into the
/// registry.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryReader : IRegistryReader
{
    /// <inheritdoc />
    public bool SupportsWow64Views => System.Environment.Is64BitOperatingSystem;

    /// <inheritdoc />
    public IRegistryKey? OpenKey(RegistryHiveKind hive, string path, RegistryViewKind view = RegistryViewKind.Default)
    {
        ArgumentNullException.ThrowIfNull(path);

        var baseKey = RegistryKey.OpenBaseKey(Map(hive), Map(view));

        try
        {
            var key = baseKey.OpenSubKey(path, writable: false);

            if (key is null)
            {
                baseKey.Dispose();
                return null;
            }

            return new WindowsRegistryKey(baseKey, key, $"{Describe(hive)}\\{path}");
        }
        catch
        {
            baseKey.Dispose();
            throw;
        }
    }

    private static RegistryHive Map(RegistryHiveKind hive) => hive switch
    {
        RegistryHiveKind.LocalMachine => RegistryHive.LocalMachine,
        RegistryHiveKind.CurrentUser => RegistryHive.CurrentUser,
        RegistryHiveKind.Users => RegistryHive.Users,
        RegistryHiveKind.ClassesRoot => RegistryHive.ClassesRoot,
        _ => throw new ArgumentOutOfRangeException(nameof(hive), hive, "Unknown registry hive."),
    };

    private static RegistryView Map(RegistryViewKind view) => view switch
    {
        RegistryViewKind.Registry32 => RegistryView.Registry32,
        RegistryViewKind.Registry64 => RegistryView.Registry64,
        _ => RegistryView.Default,
    };

    private static string Describe(RegistryHiveKind hive) => hive switch
    {
        RegistryHiveKind.LocalMachine => "HKLM",
        RegistryHiveKind.CurrentUser => "HKCU",
        RegistryHiveKind.Users => "HKU",
        RegistryHiveKind.ClassesRoot => "HKCR",
        _ => hive.ToString(),
    };
}

/// <summary>A registry key opened for reading.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsRegistryKey : IRegistryKey
{
    private readonly RegistryKey _baseKey;
    private readonly RegistryKey _key;

    internal WindowsRegistryKey(RegistryKey baseKey, RegistryKey key, string path)
    {
        _baseKey = baseKey;
        _key = key;
        Path = path;
    }

    public string Path { get; }

    /// <summary>
    /// Not exposed. Reading the last write time needs <c>RegQueryInfoKey</c>,
    /// which buys little here and would add a P/Invoke surface for a field the
    /// report does not use.
    /// </summary>
    public DateTimeOffset? LastWriteTimeUtc => null;

    public IReadOnlyList<string> GetSubKeyNames() => _key.GetSubKeyNames();

    public IReadOnlyList<string> GetValueNames() => _key.GetValueNames();

    public Core.Abstractions.RegistryValue? GetValue(string name)
    {
        // DoNotExpandEnvironmentNames keeps REG_EXPAND_SZ values raw. Expansion
        // belongs to the command line parser, which knows the machine context
        // and can be tested without one.
        var value = _key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

        if (value is null && !_key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        return new Core.Abstractions.RegistryValue(name, MapKind(_key.GetValueKind(name)), value);
    }

    public IRegistryKey? OpenSubKey(string name)
    {
        var subKey = _key.OpenSubKey(name, writable: false);
        return subKey is null ? null : new WindowsSubKey(subKey, $"{Path}\\{name}");
    }

    public void Dispose()
    {
        _key.Dispose();
        _baseKey.Dispose();
    }

    internal static CoreRegistryValueKind MapKind(Microsoft.Win32.RegistryValueKind kind) => kind switch
    {
        Microsoft.Win32.RegistryValueKind.String => CoreRegistryValueKind.String,
        Microsoft.Win32.RegistryValueKind.ExpandString => CoreRegistryValueKind.ExpandString,
        Microsoft.Win32.RegistryValueKind.MultiString => CoreRegistryValueKind.MultiString,
        Microsoft.Win32.RegistryValueKind.DWord => CoreRegistryValueKind.DWord,
        Microsoft.Win32.RegistryValueKind.QWord => CoreRegistryValueKind.QWord,
        Microsoft.Win32.RegistryValueKind.Binary => CoreRegistryValueKind.Binary,
        _ => CoreRegistryValueKind.Unknown,
    };
}

/// <summary>A subkey that owns only its own handle.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsSubKey : IRegistryKey
{
    private readonly RegistryKey _key;

    internal WindowsSubKey(RegistryKey key, string path)
    {
        _key = key;
        Path = path;
    }

    public string Path { get; }

    public DateTimeOffset? LastWriteTimeUtc => null;

    public IReadOnlyList<string> GetSubKeyNames() => _key.GetSubKeyNames();

    public IReadOnlyList<string> GetValueNames() => _key.GetValueNames();

    public Core.Abstractions.RegistryValue? GetValue(string name)
    {
        var value = _key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

        if (value is null && !_key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        return new Core.Abstractions.RegistryValue(name, WindowsRegistryKey.MapKind(_key.GetValueKind(name)), value);
    }

    public IRegistryKey? OpenSubKey(string name)
    {
        var subKey = _key.OpenSubKey(name, writable: false);
        return subKey is null ? null : new WindowsSubKey(subKey, $"{Path}\\{name}");
    }

    public void Dispose() => _key.Dispose();
}
