namespace HoongSystemScope.Core.Abstractions;

/// <summary>The registry root keys this tool reads from.</summary>
public enum RegistryHiveKind
{
    /// <summary>HKEY_LOCAL_MACHINE.</summary>
    LocalMachine = 0,

    /// <summary>HKEY_CURRENT_USER.</summary>
    CurrentUser,

    /// <summary>HKEY_USERS.</summary>
    Users,

    /// <summary>HKEY_CLASSES_ROOT.</summary>
    ClassesRoot,
}

/// <summary>
/// Which registry view to read.
/// </summary>
/// <remarks>
/// On a 64 bit system a 32 bit application writing to
/// <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</c> is silently
/// redirected to <c>...\WOW6432Node\...</c>. Both views have to be read or half
/// the autostart entries of a typical machine are invisible.
/// </remarks>
public enum RegistryViewKind
{
    /// <summary>The native view of the calling process.</summary>
    Default = 0,

    /// <summary>The 32 bit (WOW6432Node) view.</summary>
    Registry32,

    /// <summary>The 64 bit view.</summary>
    Registry64,
}

/// <summary>Type of a registry value, reduced to what this tool distinguishes.</summary>
public enum RegistryValueKind
{
    /// <summary>Unknown or unsupported type.</summary>
    Unknown = 0,

    /// <summary>REG_SZ.</summary>
    String,

    /// <summary>REG_EXPAND_SZ.</summary>
    ExpandString,

    /// <summary>REG_MULTI_SZ.</summary>
    MultiString,

    /// <summary>REG_DWORD.</summary>
    DWord,

    /// <summary>REG_QWORD.</summary>
    QWord,

    /// <summary>REG_BINARY.</summary>
    Binary,
}

/// <summary>A registry value as read by <see cref="IRegistryKey"/>.</summary>
/// <param name="Name">Value name. Empty for the default value.</param>
/// <param name="Kind">Type of the value.</param>
/// <param name="Value">The raw value, or null when it could not be read.</param>
public sealed record RegistryValue(string Name, RegistryValueKind Kind, object? Value)
{
    /// <summary>The value rendered as a string, or null.</summary>
    public string? AsString() => Value switch
    {
        null => null,
        string s => s,
        string[] multi => string.Join(Environment.NewLine, multi),
        byte[] => null,
        _ => Convert.ToString(Value, System.Globalization.CultureInfo.InvariantCulture),
    };

    /// <summary>The value as an integer, or null when it is not numeric.</summary>
    public int? AsInt32() => Value switch
    {
        int i => i,
        long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
        _ => null,
    };
}
