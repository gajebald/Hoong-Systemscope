namespace HoongSystemScope.Core.Models;

/// <summary>
/// Coarse risk bucket derived from the accumulated risk score.
/// </summary>
/// <remarks>
/// The level is presentation only. The authoritative information is the list of
/// <see cref="RiskReason"/> instances attached to an entry: every point of the
/// score can be traced back to a named rule.
/// </remarks>
public enum RiskLevel
{
    /// <summary>Nothing noteworthy. Listed for completeness.</summary>
    Informational = 0,

    /// <summary>Slightly unusual, almost always benign.</summary>
    Low,

    /// <summary>Worth a look.</summary>
    Medium,

    /// <summary>Several indicators combined, should be reviewed.</summary>
    High,

    /// <summary>Strong combination of indicators.</summary>
    Critical,
}
