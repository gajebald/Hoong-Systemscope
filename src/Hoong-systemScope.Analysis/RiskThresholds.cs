using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis;

/// <summary>
/// Maps an accumulated score onto a <see cref="RiskLevel"/>.
/// </summary>
/// <remarks>
/// The thresholds are deliberately conservative. A diagnostic tool that paints
/// half the machine red teaches its user to ignore it, and then it has made
/// things worse rather than better. Reaching High should require two or three
/// independent indicators, not one.
/// </remarks>
public sealed record RiskThresholds
{
    /// <summary>Score at which an entry becomes <see cref="RiskLevel.Low"/>.</summary>
    public int Low { get; init; } = 10;

    /// <summary>Score at which an entry becomes <see cref="RiskLevel.Medium"/>.</summary>
    public int Medium { get; init; } = 25;

    /// <summary>Score at which an entry becomes <see cref="RiskLevel.High"/>.</summary>
    public int High { get; init; } = 45;

    /// <summary>Score at which an entry becomes <see cref="RiskLevel.Critical"/>.</summary>
    public int Critical { get; init; } = 70;

    /// <summary>The shipped defaults.</summary>
    public static RiskThresholds Default { get; } = new();

    /// <summary>Buckets a score.</summary>
    public RiskLevel Classify(int score) => score switch
    {
        var s when s >= Critical => RiskLevel.Critical,
        var s when s >= High => RiskLevel.High,
        var s when s >= Medium => RiskLevel.Medium,
        var s when s >= Low => RiskLevel.Low,
        _ => RiskLevel.Informational,
    };
}
