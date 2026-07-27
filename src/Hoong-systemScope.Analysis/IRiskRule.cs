using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis;

/// <summary>One named risk indicator.</summary>
/// <remarks>
/// A rule looks at a single entry and either stays silent or returns exactly
/// one reason. Keeping rules independent and side effect free is what makes the
/// resulting score explainable and each rule testable on its own.
/// </remarks>
public interface IRiskRule
{
    /// <summary>Stable identifier of the rule.</summary>
    string RuleId { get; }

    /// <summary>Evaluates the entry, returning null when the rule does not apply.</summary>
    RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context);
}

/// <summary>Machine facts a rule may need beyond the entry itself.</summary>
public sealed class RiskEvaluationContext
{
    /// <summary>Creates a context.</summary>
    /// <param name="windowsDirectory">Windows directory of the scanned machine.</param>
    /// <param name="isDirectoryWritableByStandardUsers">
    /// Answers whether a directory can be written to by a non-administrator.
    /// Passed as a delegate so the analysis project stays free of file system
    /// access and remains testable without one.
    /// </param>
    public RiskEvaluationContext(
        string windowsDirectory,
        Func<string, bool>? isDirectoryWritableByStandardUsers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(windowsDirectory);

        WindowsDirectory = windowsDirectory;
        IsDirectoryWritableByStandardUsers = isDirectoryWritableByStandardUsers ?? (_ => false);
    }

    /// <summary>Windows directory of the scanned machine.</summary>
    public string WindowsDirectory { get; }

    /// <summary>Whether a directory is writable by standard users.</summary>
    public Func<string, bool> IsDirectoryWritableByStandardUsers { get; }

    /// <summary>A context for a default Windows installation.</summary>
    public static RiskEvaluationContext Default { get; } = new(@"C:\Windows");
}
