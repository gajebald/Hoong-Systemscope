namespace HoongSystemScope.Core.Text;

/// <summary>The result of splitting a raw command line into program and arguments.</summary>
public sealed record ParsedCommandLine
{
    /// <summary>The executable, normalised and with environment variables expanded.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Everything after the executable, or null when there are no arguments.</summary>
    public string? Arguments { get; init; }

    /// <summary>True when the executable was enclosed in quotes in the raw value.</summary>
    public bool WasQuoted { get; init; }

    /// <summary>
    /// True when the executable was not quoted although its path contains a
    /// space. Windows then probes every space-delimited prefix, so an attacker
    /// who can create <c>C:\Program.exe</c> takes over the entry. The risk
    /// engine turns this flag into a finding for services.
    /// </summary>
    public bool HasUnquotedPathWithSpaces { get; init; }

    /// <summary>True when nothing usable could be extracted.</summary>
    public bool IsEmpty => string.IsNullOrEmpty(ExecutablePath);

    /// <summary>An empty result.</summary>
    public static ParsedCommandLine Empty { get; } = new();
}
