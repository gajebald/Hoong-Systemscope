namespace HoongSystemScope.Cli;

/// <summary>
/// Process exit codes.
/// </summary>
/// <remarks>
/// The distinction between <see cref="FindingsAboveThreshold"/> and
/// <see cref="PartialResults"/> is what makes the tool usable from a script: a
/// scan that found something is a different situation from a scan that could
/// not see the whole machine, and conflating them would make automation act on
/// the wrong one.
/// </remarks>
public static class ExitCodes
{
    /// <summary>The scan completed and nothing reached the reporting threshold.</summary>
    public const int Success = 0;

    /// <summary>The scan completed and at least one entry reached the threshold.</summary>
    public const int FindingsAboveThreshold = 1;

    /// <summary>The scan completed, but at least one collector failed.</summary>
    public const int PartialResults = 2;

    /// <summary>The command line was wrong.</summary>
    public const int UsageError = 3;

    /// <summary>The scan could not run at all.</summary>
    public const int FatalError = 4;

    /// <summary>The user cancelled the scan.</summary>
    public const int Cancelled = 5;
}
