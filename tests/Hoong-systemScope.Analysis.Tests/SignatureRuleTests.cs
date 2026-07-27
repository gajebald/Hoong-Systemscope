using HoongSystemScope.Analysis.Rules;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Analysis.Tests;

public sealed class SignatureRuleTests
{
    private static readonly RiskEvaluationContext Context = RiskEvaluationContext.Default;

    [Fact]
    public void Unsigned_binary_is_flagged_but_only_mildly()
    {
        var reason = new UnsignedBinaryRule().Evaluate(
            EntryBuilder.Create(signatureStatus: SignatureStatus.Unsigned),
            Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_UNSIGNED", reason.Code);

        // Plenty of legitimate software ships unsigned. On its own this must
        // not be enough to reach Medium.
        Assert.True(reason.ScoreDelta < RiskThresholds.Default.Medium);
    }

    [Fact]
    public void A_catalog_signature_counts_as_signed()
    {
        // Most Windows system binaries have no embedded signature. Treating
        // them as unsigned would bury the report in false positives.
        var reason = new UnsignedBinaryRule().Evaluate(
            EntryBuilder.Create(signatureStatus: SignatureStatus.ValidCatalog),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void A_missing_file_is_not_also_reported_as_unsigned()
    {
        var reason = new UnsignedBinaryRule().Evaluate(
            EntryBuilder.Create(fileExists: false, signatureStatus: SignatureStatus.FileNotFound),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void A_hosts_entry_is_never_judged_as_a_binary()
    {
        var reason = new UnsignedBinaryRule().Evaluate(
            EntryBuilder.Create(
                category: ScanCategory.HostsFile,
                executablePath: null,
                signatureStatus: SignatureStatus.Unsigned),
            Context);

        Assert.Null(reason);
    }

    [Theory]
    [InlineData(SignatureStatus.Invalid, "RISK_SIGNATURE_INVALID")]
    [InlineData(SignatureStatus.Revoked, "RISK_SIGNATURE_REVOKED")]
    [InlineData(SignatureStatus.UntrustedRoot, "RISK_SIGNATURE_UNTRUSTED_ROOT")]
    [InlineData(SignatureStatus.Expired, "RISK_SIGNATURE_EXPIRED")]
    public void A_broken_signature_is_reported_with_its_specific_code(SignatureStatus status, string expectedCode)
    {
        var reason = new BrokenSignatureRule().Evaluate(EntryBuilder.Create(signatureStatus: status), Context);

        Assert.NotNull(reason);
        Assert.Equal(expectedCode, reason.Code);
    }

    [Fact]
    public void A_tampered_signature_outweighs_a_missing_one()
    {
        // "Was signed and no longer verifies" means something changed the file;
        // "never signed" does not.
        var invalid = new BrokenSignatureRule().Evaluate(
            EntryBuilder.Create(signatureStatus: SignatureStatus.Invalid), Context);
        var unsigned = new UnsignedBinaryRule().Evaluate(
            EntryBuilder.Create(signatureStatus: SignatureStatus.Unsigned), Context);

        Assert.NotNull(invalid);
        Assert.NotNull(unsigned);
        Assert.True(invalid.ScoreDelta > unsigned.ScoreDelta);
    }

    [Fact]
    public void A_microsoft_binary_in_system32_lowers_the_score()
    {
        var reason = new TrustedSystemBinaryRule().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Windows\System32\svchost.exe",
                signature: EntryBuilder.MicrosoftSignature),
            Context);

        Assert.NotNull(reason);
        Assert.True(reason.ScoreDelta < 0);
    }

    [Fact]
    public void A_microsoft_signature_outside_system32_earns_no_credit()
    {
        // Signed by Microsoft but sitting in a temp directory is not reassuring.
        var reason = new TrustedSystemBinaryRule().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Users\bob\AppData\Local\Temp\svchost.exe",
                signature: EntryBuilder.MicrosoftSignature),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void An_unknown_publisher_in_system32_earns_no_credit()
    {
        var reason = new TrustedSystemBinaryRule().Evaluate(
            EntryBuilder.Create(
                executablePath: @"C:\Windows\System32\odd.exe",
                signature: new SignatureInfo { Status = SignatureStatus.Valid, SubjectName = "Some Vendor GmbH" }),
            Context);

        Assert.Null(reason);
    }

    [Fact]
    public void A_missing_target_is_reported()
    {
        var reason = new MissingTargetRule().Evaluate(
            EntryBuilder.Create(fileExists: false, executablePath: @"C:\gone\app.exe"),
            Context);

        Assert.NotNull(reason);
        Assert.Equal("RISK_MISSING_TARGET", reason.Code);
    }
}
