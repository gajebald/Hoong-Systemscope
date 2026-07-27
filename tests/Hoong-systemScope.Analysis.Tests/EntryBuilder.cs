using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Analysis.Tests;

/// <summary>Builds scan entries for rule tests without repeating the required members.</summary>
internal static class EntryBuilder
{
    public static ScanEntry Create(
        ScanCategory category = ScanCategory.RegistryRun,
        string name = "Sample",
        string location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        string? executablePath = @"C:\Program Files\Vendor\app.exe",
        string? commandLine = null,
        string? arguments = null,
        string? userName = null,
        bool? isEnabled = true,
        bool? fileExists = true,
        string? publisher = null,
        string? sha256 = null,
        SignatureStatus signatureStatus = SignatureStatus.NotChecked,
        SignatureInfo? signature = null,
        IReadOnlyDictionary<string, string?>? metadata = null) => new()
    {
        Id = EntryIdentity.Compute(category, location, name),
        Category = category,
        Name = name,
        Location = location,
        ExecutablePath = executablePath,
        CommandLine = commandLine,
        Arguments = arguments,
        UserName = userName,
        IsEnabled = isEnabled,
        FileExists = fileExists,
        Publisher = publisher,
        Sha256 = sha256,
        SignatureStatus = signature?.Status ?? signatureStatus,
        Signature = signature ?? new SignatureInfo { Status = signatureStatus },
        Metadata = metadata ?? new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase),
        CollectedAtUtc = DateTimeOffset.UnixEpoch,
    };

    public static SignatureInfo MicrosoftSignature { get; } = new()
    {
        Status = SignatureStatus.Valid,
        SubjectName = "Microsoft Windows",
        IssuerName = "Microsoft Windows Production PCA 2011",
    };

    public static Dictionary<string, string?> Metadata(params (string Key, string? Value)[] pairs)
    {
        var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var (key, value) in pairs)
        {
            metadata[key] = value;
        }

        return metadata;
    }
}
