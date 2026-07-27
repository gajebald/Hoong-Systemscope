using System.Text.RegularExpressions;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.TestSupport;

/// <summary>A deterministic stand-in for the real machine environment.</summary>
public sealed partial class FakeEnvironment : IEnvironmentProbe
{
    private readonly Dictionary<string, string> _variables = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SystemRoot"] = @"C:\Windows",
        ["WinDir"] = @"C:\Windows",
        ["SystemDrive"] = "C:",
        ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
        ["UserProfile"] = @"C:\Users\tester",
        ["AppData"] = @"C:\Users\tester\AppData\Roaming",
        ["LocalAppData"] = @"C:\Users\tester\AppData\Local",
        ["Temp"] = @"C:\Users\tester\AppData\Local\Temp",
    };

    public string WindowsDirectory { get; set; } = @"C:\Windows";

    public string SystemDirectory { get; set; } = @"C:\Windows\System32";

    public string? SystemDirectoryWow64 { get; set; } = @"C:\Windows\SysWOW64";

    public string? CurrentUserStartupFolder { get; set; } =
        @"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

    public string? CommonStartupFolder { get; set; } =
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup";

    public IReadOnlyList<string> TemporaryDirectories { get; set; } =
    [
        @"C:\Users\tester\AppData\Local\Temp",
        @"C:\Windows\Temp",
    ];

    public string HostsFilePath { get; set; } = @"C:\Windows\System32\drivers\etc\hosts";

    public List<UserProfile> UserProfiles { get; } = [];

    public MachineInfo Machine { get; set; } = new()
    {
        MachineName = "TESTMACHINE",
        OperatingSystem = "Microsoft Windows 10.0.22631",
        Architecture = "X64",
        UserName = @"TESTMACHINE\tester",
        IsElevated = false,
        Is64BitOperatingSystem = true,
    };

    /// <summary>Sets an environment variable used by <see cref="ExpandEnvironmentVariables"/>.</summary>
    public FakeEnvironment WithVariable(string name, string value)
    {
        _variables[name] = value;
        return this;
    }

    public MachineInfo GetMachineInfo() => Machine;

    public string ExpandEnvironmentVariables(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return VariablePattern().Replace(value, match =>
        {
            var name = match.Groups[1].Value;
            return _variables.TryGetValue(name, out var replacement) ? replacement : match.Value;
        });
    }

    public IReadOnlyList<UserProfile> GetUserProfiles() => UserProfiles;

    [GeneratedRegex("%([^%]+)%")]
    private static partial Regex VariablePattern();
}
