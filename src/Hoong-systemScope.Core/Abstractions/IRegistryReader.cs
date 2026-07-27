namespace HoongSystemScope.Core.Abstractions;

/// <summary>
/// An open registry key, restricted to reading.
/// </summary>
/// <remarks>
/// There is intentionally no write, create or delete member anywhere on this
/// interface or on <see cref="IRegistryReader"/>. Read-only behaviour is not a
/// runtime flag that could be flipped; it is enforced by the type system.
/// </remarks>
public interface IRegistryKey : IDisposable
{
    /// <summary>Full path of the key, including the hive.</summary>
    string Path { get; }

    /// <summary>Names of the direct child keys.</summary>
    IReadOnlyList<string> GetSubKeyNames();

    /// <summary>Names of the values stored directly in this key.</summary>
    IReadOnlyList<string> GetValueNames();

    /// <summary>Reads a single value, or null when it does not exist.</summary>
    /// <param name="name">Value name. Use an empty string for the default value.</param>
    RegistryValue? GetValue(string name);

    /// <summary>Opens a child key, or returns null when it does not exist or is inaccessible.</summary>
    IRegistryKey? OpenSubKey(string name);

    /// <summary>Time the key was last written to, when the platform exposes it.</summary>
    DateTimeOffset? LastWriteTimeUtc { get; }
}

/// <summary>Read-only access to the Windows registry.</summary>
public interface IRegistryReader
{
    /// <summary>
    /// Opens a key for reading, or returns null when it does not exist or the
    /// caller lacks permission.
    /// </summary>
    /// <param name="hive">Root key.</param>
    /// <param name="path">Path below the root key.</param>
    /// <param name="view">Which registry view to use.</param>
    IRegistryKey? OpenKey(RegistryHiveKind hive, string path, RegistryViewKind view = RegistryViewKind.Default);

    /// <summary>True when the machine has a distinct 32 bit registry view.</summary>
    bool SupportsWow64Views { get; }
}
