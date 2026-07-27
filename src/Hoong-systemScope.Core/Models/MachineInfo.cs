namespace HoongSystemScope.Core.Models;

/// <summary>
/// Minimal description of the scanned machine.
/// </summary>
/// <remarks>
/// Deliberately limited to what is needed to interpret a report. No serial
/// numbers, no machine GUID, no account SIDs: a diagnostic report is frequently
/// shared with third parties for help, and it should not carry identifiers
/// beyond what the reader actually needs.
/// </remarks>
public sealed record MachineInfo
{
    /// <summary>Host name of the machine.</summary>
    public required string MachineName { get; init; }

    /// <summary>Operating system description, for example <c>Microsoft Windows 10.0.22631</c>.</summary>
    public required string OperatingSystem { get; init; }

    /// <summary>Process architecture, for example <c>X64</c>.</summary>
    public required string Architecture { get; init; }

    /// <summary>Name of the account running the scan.</summary>
    public required string UserName { get; init; }

    /// <summary>True when the scan ran with administrative privileges.</summary>
    public required bool IsElevated { get; init; }

    /// <summary>True when the tool ran on a 64 bit operating system.</summary>
    public bool Is64BitOperatingSystem { get; init; }
}
