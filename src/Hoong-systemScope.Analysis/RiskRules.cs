using HoongSystemScope.Analysis.Rules;

namespace HoongSystemScope.Analysis;

/// <summary>The rule set shipped with Hoong-systemScope.</summary>
/// <remarks>
/// Scores and thresholds are documented in <c>docs/risk-rules.md</c>. They are
/// intentionally cautious: reaching High normally takes two or three
/// independent indicators, because a tool that flags everything gets ignored.
/// </remarks>
public static class RiskRules
{
    /// <summary>Creates a fresh instance of every built-in rule.</summary>
    public static IReadOnlyList<IRiskRule> CreateDefaultSet() =>
    [
        new UnsignedBinaryRule(),
        new BrokenSignatureRule(),
        new TrustedSystemBinaryRule(),
        new MissingTargetRule(),
        new SuspiciousLocationRule(),
        new WritableDirectoryRule(),
        new UnquotedServicePathRule(),
        new DeceptiveNameRule(),
        new ScriptInterpreterRule(),
        new ObfuscatedCommandRule(),
        new SensitivePersistenceRule(),
        new HiddenTaskRule(),
        new HostsRedirectRule(),
    ];
}
