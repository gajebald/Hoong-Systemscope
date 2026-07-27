namespace HoongSystemScope.Core.Models;

/// <summary>
/// One finding: an autostart entry, a service, a scheduled task, a process or
/// any other persistence point discovered by a collector.
/// </summary>
/// <remarks>
/// Instances are immutable. Collectors produce a bare entry, the enrichment
/// pipeline fills in the file facts (<see cref="Sha256"/>, publisher,
/// signature) and the risk engine fills in <see cref="RiskScore"/>,
/// <see cref="RiskLevel"/> and <see cref="RiskReasons"/>.
/// </remarks>
public sealed record ScanEntry
{
    /// <summary>
    /// Stable identity of the entry, derived from category, location and name
    /// only. Volatile facts such as the hash are deliberately excluded so that
    /// the same entry can be matched across two scans even when the file behind
    /// it was replaced.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>Where in the system this entry lives.</summary>
    public required ScanCategory Category { get; init; }

    /// <summary>Name of the entry, for example the registry value name or the service name.</summary>
    public required string Name { get; init; }

    /// <summary>Fully qualified source, for example the registry key path or the task folder.</summary>
    public required string Location { get; init; }

    /// <summary>Raw command line as stored in the system.</summary>
    public string? CommandLine { get; init; }

    /// <summary>Executable resolved from <see cref="CommandLine"/>.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Arguments resolved from <see cref="CommandLine"/>.</summary>
    public string? Arguments { get; init; }

    /// <summary>Account the entry runs as, where the system exposes it.</summary>
    public string? UserName { get; init; }

    /// <summary>Whether the entry is currently active. Null when the concept does not apply.</summary>
    public bool? IsEnabled { get; init; }

    /// <summary>Whether <see cref="ExecutablePath"/> exists. Null when no path could be resolved.</summary>
    public bool? FileExists { get; init; }

    /// <summary>Company name from the file's version resource.</summary>
    public string? Publisher { get; init; }

    /// <summary>Product name from the file's version resource.</summary>
    public string? ProductName { get; init; }

    /// <summary>File description from the file's version resource.</summary>
    public string? FileDescription { get; init; }

    /// <summary>File version from the file's version resource.</summary>
    public string? FileVersion { get; init; }

    /// <summary>Lower case hexadecimal SHA-256 of the executable.</summary>
    public string? Sha256 { get; init; }

    /// <summary>Authenticode verification result.</summary>
    public SignatureStatus SignatureStatus { get; init; }

    /// <summary>Details of the Authenticode verification.</summary>
    public SignatureInfo? Signature { get; init; }

    /// <summary>Risk bucket derived from <see cref="RiskScore"/>.</summary>
    public RiskLevel RiskLevel { get; init; }

    /// <summary>Sum of all <see cref="RiskReason.ScoreDelta"/> values, clamped to zero or above.</summary>
    public int RiskScore { get; init; }

    /// <summary>Every rule hit that contributed to <see cref="RiskScore"/>.</summary>
    public IReadOnlyList<RiskReason> RiskReasons { get; init; } = Array.Empty<RiskReason>();

    /// <summary>Category specific extras, for example a service start type or a task trigger summary.</summary>
    public IReadOnlyDictionary<string, string?> Metadata { get; init; } =
        new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

    /// <summary>When the entry was collected.</summary>
    public DateTimeOffset CollectedAtUtc { get; init; }
}
