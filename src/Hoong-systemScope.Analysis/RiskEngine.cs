using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis;

/// <summary>
/// Applies every rule to every entry and turns the hits into a score.
/// </summary>
/// <remarks>
/// The score is a sum, clamped at zero, and every point in it belongs to a
/// named rule that is carried along on the entry. That traceability is the
/// deliverable: a number nobody can explain is worse than no number at all,
/// because it invites the user to act on it without understanding it.
/// </remarks>
public sealed class RiskEngine
{
    private readonly IReadOnlyList<IRiskRule> _rules;
    private readonly RiskThresholds _thresholds;

    /// <summary>Creates an engine over the given rules.</summary>
    public RiskEngine(IEnumerable<IRiskRule> rules, RiskThresholds? thresholds = null)
    {
        ArgumentNullException.ThrowIfNull(rules);

        _rules = rules.ToArray();
        _thresholds = thresholds ?? RiskThresholds.Default;
    }

    /// <summary>An engine with the built-in rule set and default thresholds.</summary>
    public static RiskEngine CreateDefault(RiskThresholds? thresholds = null) =>
        new(RiskRules.CreateDefaultSet(), thresholds);

    /// <summary>The rules this engine applies.</summary>
    public IReadOnlyList<IRiskRule> Rules => _rules;

    /// <summary>Scores a single entry, returning a copy with the verdict attached.</summary>
    public ScanEntry Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var reasons = new List<RiskReason>();
        var score = 0;

        foreach (var rule in _rules)
        {
            var reason = rule.Evaluate(entry, context);
            if (reason is null)
            {
                continue;
            }

            reasons.Add(reason);
            score += reason.ScoreDelta;
        }

        // A mitigating rule may push the total below zero. Clamping keeps the
        // scale meaningful without discarding the reason from the explanation.
        score = Math.Max(0, score);

        return entry with
        {
            RiskScore = score,
            RiskLevel = _thresholds.Classify(score),
            RiskReasons = reasons
                .OrderByDescending(r => r.ScoreDelta)
                .ThenBy(r => r.RuleId, StringComparer.Ordinal)
                .ToArray(),
        };
    }

    /// <summary>Scores every entry of a scan and refreshes its summary.</summary>
    public ScanResult Evaluate(ScanResult result, RiskEvaluationContext context)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(context);

        var entries = result.Entries.Select(e => Evaluate(e, context)).ToArray();

        return result with
        {
            Entries = entries,
            Summary = ScanSummaryBuilder.Build(entries),
        };
    }
}
