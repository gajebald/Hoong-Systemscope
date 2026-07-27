namespace HoongSystemScope.Core.Models;

/// <summary>
/// A single, named contribution to an entry's risk score.
/// </summary>
/// <remarks>
/// Every point in <see cref="ScanEntry.RiskScore"/> originates from exactly one
/// of these. That is what makes a rating explainable rather than an opaque
/// number, and the text report prints the reasons verbatim.
/// </remarks>
public sealed record RiskReason
{
    /// <summary>Identifier of the rule that produced this reason, for example <c>UnsignedBinary</c>.</summary>
    public required string RuleId { get; init; }

    /// <summary>Short, stable machine readable code, for example <c>RISK_UNSIGNED</c>.</summary>
    public required string Code { get; init; }

    /// <summary>One line summary shown in reports.</summary>
    public required string Title { get; init; }

    /// <summary>Concrete detail for this entry, for example the offending path.</summary>
    public string? Detail { get; init; }

    /// <summary>
    /// Points added to the entry's score. Negative values are allowed and are
    /// used by mitigating rules such as "Microsoft signed and located below
    /// System32".
    /// </summary>
    public required int ScoreDelta { get; init; }
}
