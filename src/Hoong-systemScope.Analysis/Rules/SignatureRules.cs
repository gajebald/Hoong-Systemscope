using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Analysis.Rules;

/// <summary>Convenience base that turns a predicate into a rule.</summary>
public abstract class RiskRuleBase : IRiskRule
{
    /// <inheritdoc />
    public abstract string RuleId { get; }

    /// <inheritdoc />
    public abstract RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context);

    /// <summary>Builds a reason attributed to this rule.</summary>
    protected RiskReason Reason(string code, string title, int scoreDelta, string? detail = null) => new()
    {
        RuleId = RuleId,
        Code = code,
        Title = title,
        Detail = detail,
        ScoreDelta = scoreDelta,
    };

    /// <summary>
    /// True for entries that name a file worth judging. A hosts file mapping
    /// has no binary behind it, so file-oriented rules must stay silent there
    /// rather than report every line as unsigned.
    /// </summary>
    protected static bool HasInspectableFile(ScanEntry entry) =>
        !string.IsNullOrWhiteSpace(entry.ExecutablePath) && entry.Category != ScanCategory.HostsFile;
}

/// <summary>Flags a binary that carries no trust at all.</summary>
public sealed class UnsignedBinaryRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "UnsignedBinary";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (!HasInspectableFile(entry) || entry.FileExists == false)
        {
            return null;
        }

        // Plenty of legitimate software ships unsigned, so this alone is a
        // nudge rather than a verdict. It gains weight in combination with the
        // location and interpreter rules.
        return entry.SignatureStatus == SignatureStatus.Unsigned
            ? Reason("RISK_UNSIGNED", "The file carries no digital signature.", 12, entry.ExecutablePath)
            : null;
    }
}

/// <summary>Flags a signature that is present but does not hold up.</summary>
public sealed class BrokenSignatureRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "BrokenSignature";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (!HasInspectableFile(entry))
        {
            return null;
        }

        // A file that was signed and no longer verifies is a much stronger
        // signal than one that was never signed: something changed it after the
        // fact.
        return entry.SignatureStatus switch
        {
            SignatureStatus.Invalid => Reason(
                "RISK_SIGNATURE_INVALID",
                "The file was signed, but the signature no longer matches its content.",
                40,
                entry.ExecutablePath),
            SignatureStatus.Revoked => Reason(
                "RISK_SIGNATURE_REVOKED",
                "The signing certificate was revoked.",
                45,
                entry.Signature?.SubjectName),
            SignatureStatus.UntrustedRoot => Reason(
                "RISK_SIGNATURE_UNTRUSTED_ROOT",
                "The signature chains to a root this machine does not trust.",
                25,
                entry.Signature?.IssuerName),
            SignatureStatus.Expired => Reason(
                "RISK_SIGNATURE_EXPIRED",
                "The signature expired and carries no valid timestamp.",
                10,
                entry.Signature?.SubjectName),
            _ => null,
        };
    }
}

/// <summary>Rewards a Microsoft-signed binary sitting where Windows keeps its own.</summary>
public sealed class TrustedSystemBinaryRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "TrustedSystemBinary";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (!HasInspectableFile(entry) || entry.Signature?.IsTrusted != true)
        {
            return null;
        }

        var location = PathFacts.Classify(entry.ExecutablePath, context.WindowsDirectory);
        var isSystemLocation =
            location.HasFlag(PathLocationKind.SystemDirectory) ||
            location.HasFlag(PathLocationKind.ComponentStore);

        if (!isSystemLocation || !IsMicrosoft(entry))
        {
            return null;
        }

        // Both halves are required. A Microsoft-signed binary in a temp
        // directory is not reassuring, and neither is an unknown publisher in
        // System32.
        return Reason(
            "RISK_TRUSTED_SYSTEM_BINARY",
            "Signed by Microsoft and located in the Windows system directory.",
            -8,
            entry.ExecutablePath);
    }

    private static bool IsMicrosoft(ScanEntry entry)
    {
        var subject = entry.Signature?.SubjectName;
        var publisher = entry.Publisher;

        return (subject is not null && subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) ||
               (publisher is not null && publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>Flags an entry whose target no longer exists.</summary>
public sealed class MissingTargetRule : RiskRuleBase
{
    /// <inheritdoc />
    public override string RuleId => "MissingTarget";

    /// <inheritdoc />
    public override RiskReason? Evaluate(ScanEntry entry, RiskEvaluationContext context)
    {
        if (entry.FileExists != false || string.IsNullOrWhiteSpace(entry.ExecutablePath))
        {
            return null;
        }

        // Usually leftover clutter from an uninstall. It matters because the
        // path is now free for anyone who can write there to claim.
        return Reason(
            "RISK_MISSING_TARGET",
            "The entry points at a file that does not exist.",
            8,
            entry.ExecutablePath);
    }
}
