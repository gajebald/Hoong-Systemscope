using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;
using HoongSystemScope.ViewModels;

namespace HoongSystemScope.ViewModels.Tests;

/// <summary>A scan service that returns whatever the test configured.</summary>
internal sealed class FakeScanService : IScanService
{
    private readonly Dictionary<string, ScanResult> _saved = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>What <see cref="ScanAsync"/> returns.</summary>
    public ScanResult Result { get; set; } = ScanBuilder.Result();

    /// <summary>When set, <see cref="ScanAsync"/> throws it instead of returning.</summary>
    public Exception? Failure { get; set; }

    /// <summary>Progress updates the fake emits before returning.</summary>
    public List<ScanProgressUpdate> ProgressUpdates { get; } = [];

    /// <summary>Number of scans started.</summary>
    public int ScanCount { get; private set; }

    /// <summary>Signals the fake to block until released, so cancellation can be tested.</summary>
    public TaskCompletionSource? Gate { get; set; }

    public async Task<ScanResult> ScanAsync(
        ScanOptions options,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken cancellationToken)
    {
        ScanCount++;

        foreach (var update in ProgressUpdates)
        {
            progress?.Report(update);
        }

        if (Gate is not null)
        {
            await Gate.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (Failure is not null)
        {
            throw Failure;
        }

        return Result;
    }

    public string Render(ScanResult result, ReportFormat format) => $"rendered-scan-{format}";

    public string Render(BaselineDiff diff, ReportFormat format) => $"rendered-diff-{format}";

    public Task<ScanResult> LoadAsync(string path, CancellationToken cancellationToken) =>
        _saved.TryGetValue(path, out var result)
            ? Task.FromResult(result)
            : Task.FromException<ScanResult>(new FileNotFoundException($"No scan at '{path}'.", path));

    public Task SaveAsync(ScanResult result, string path, CancellationToken cancellationToken)
    {
        _saved[path] = result;
        return Task.CompletedTask;
    }

    /// <summary>Pre-populates a path so it can be loaded or compared against.</summary>
    public FakeScanService WithSavedScan(string path, ScanResult result)
    {
        _saved[path] = result;
        return this;
    }
}

/// <summary>Builds scan results for the view model tests.</summary>
internal static class ScanBuilder
{
    public static ScanEntry Entry(
        string name = "Updater",
        ScanCategory category = ScanCategory.RegistryRun,
        string location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        string? executablePath = @"C:\Program Files\Vendor\updater.exe",
        string? publisher = "Vendor GmbH",
        bool? fileExists = true,
        SignatureStatus signatureStatus = SignatureStatus.Valid,
        RiskLevel riskLevel = RiskLevel.Informational,
        int riskScore = 0,
        IReadOnlyList<RiskReason>? reasons = null) => new()
    {
        Id = EntryIdentity.Compute(category, location, name),
        Category = category,
        Name = name,
        Location = location,
        ExecutablePath = executablePath,
        CommandLine = executablePath,
        Publisher = publisher,
        FileExists = fileExists,
        SignatureStatus = signatureStatus,
        Signature = new SignatureInfo { Status = signatureStatus },
        RiskLevel = riskLevel,
        RiskScore = riskScore,
        RiskReasons = reasons ?? [],
        CollectedAtUtc = DateTimeOffset.UnixEpoch,
    };

    public static ScanResult Result(
        IReadOnlyList<ScanEntry>? entries = null,
        IReadOnlyList<ScanError>? errors = null,
        bool isElevated = true) => new()
    {
        SchemaVersion = ScanResult.CurrentSchemaVersion,
        ToolVersion = "0.1.0-test",
        Machine = new MachineInfo
        {
            MachineName = "TESTMACHINE",
            OperatingSystem = "Microsoft Windows 10.0.22631",
            Architecture = "X64",
            UserName = @"TESTMACHINE\tester",
            IsElevated = isElevated,
            Is64BitOperatingSystem = true,
        },
        StartedAtUtc = DateTimeOffset.UnixEpoch,
        CompletedAtUtc = DateTimeOffset.UnixEpoch.AddSeconds(10),
        Entries = entries ?? [Entry()],
        Errors = errors ?? [],
    };
}
