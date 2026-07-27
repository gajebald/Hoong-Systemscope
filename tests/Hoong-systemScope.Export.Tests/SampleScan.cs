using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Export.Tests;

/// <summary>A small but representative scan used across the export tests.</summary>
internal static class SampleScan
{
    public static readonly DateTimeOffset StartedAt = new(2026, 3, 1, 8, 0, 0, TimeSpan.Zero);

    public static ScanEntry Entry(
        ScanCategory category = ScanCategory.RegistryRun,
        string name = "Updater",
        string location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        string? executablePath = @"C:\Program Files\Vendor\updater.exe",
        string? commandLine = null,
        string? arguments = null,
        bool? fileExists = true,
        string? sha256 = null,
        SignatureStatus signatureStatus = SignatureStatus.NotChecked,
        RiskLevel riskLevel = RiskLevel.Informational,
        int riskScore = 0,
        IReadOnlyList<RiskReason>? reasons = null) => new()
    {
        Id = EntryIdentity.Compute(category, location, name),
        Category = category,
        Name = name,
        Location = location,
        ExecutablePath = executablePath,
        CommandLine = commandLine,
        Arguments = arguments,
        FileExists = fileExists,
        Sha256 = sha256,
        SignatureStatus = signatureStatus,
        Signature = new SignatureInfo { Status = signatureStatus, SubjectName = "Vendor GmbH" },
        RiskLevel = riskLevel,
        RiskScore = riskScore,
        RiskReasons = reasons ?? [],
        Metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase) { ["sample"] = "yes" },
        CollectedAtUtc = StartedAt,
    };

    public static ScanResult Create(params ScanEntry[] entries) => new()
    {
        SchemaVersion = ScanResult.CurrentSchemaVersion,
        ToolVersion = "0.1.0-test",
        Machine = new MachineInfo
        {
            MachineName = "TESTMACHINE",
            OperatingSystem = "Microsoft Windows 10.0.22631",
            Architecture = "X64",
            UserName = @"TESTMACHINE\tester",
            IsElevated = true,
            Is64BitOperatingSystem = true,
        },
        StartedAtUtc = StartedAt,
        CompletedAtUtc = StartedAt.AddSeconds(12),
        Entries = entries.Length > 0 ? entries : [Entry()],
        Errors = [],
        Collectors =
        [
            new CollectorRunInfo
            {
                CollectorId = "registry-run",
                Category = ScanCategory.RegistryRun,
                EntryCount = entries.Length,
                Duration = TimeSpan.FromMilliseconds(120),
                Succeeded = true,
            },
        ],
    };
}
