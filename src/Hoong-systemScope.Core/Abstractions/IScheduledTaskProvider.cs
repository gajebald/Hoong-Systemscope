namespace HoongSystemScope.Core.Abstractions;

/// <summary>A single action of a scheduled task.</summary>
/// <param name="Kind">Action type, for example <c>Exec</c> or <c>ComHandler</c>.</param>
/// <param name="Path">Executable or COM class, depending on <paramref name="Kind"/>.</param>
/// <param name="Arguments">Arguments, when the action has any.</param>
public sealed record ScheduledTaskAction(string Kind, string? Path, string? Arguments);

/// <summary>One entry of the Windows task scheduler.</summary>
public sealed record ScheduledTaskRecord
{
    /// <summary>Full path of the task, for example <c>\Microsoft\Windows\Defrag\ScheduledDefrag</c>.</summary>
    public required string TaskPath { get; init; }

    /// <summary>Leaf name of the task.</summary>
    public required string Name { get; init; }

    /// <summary>True when the task is enabled.</summary>
    public bool? IsEnabled { get; init; }

    /// <summary>True when the task is flagged hidden and therefore not shown by the default UI.</summary>
    public bool? IsHidden { get; init; }

    /// <summary>Account the task runs as.</summary>
    public string? Principal { get; init; }

    /// <summary>Requested privilege level, for example <c>HighestAvailable</c>.</summary>
    public string? RunLevel { get; init; }

    /// <summary>Author recorded in the task definition.</summary>
    public string? Author { get; init; }

    /// <summary>Description recorded in the task definition.</summary>
    public string? Description { get; init; }

    /// <summary>Short summary of the configured triggers.</summary>
    public string? TriggerSummary { get; init; }

    /// <summary>Everything the task executes.</summary>
    public IReadOnlyList<ScheduledTaskAction> Actions { get; init; } = Array.Empty<ScheduledTaskAction>();

    /// <summary>When the task was registered, if known.</summary>
    public DateTimeOffset? RegistrationDateUtc { get; init; }
}

/// <summary>Enumerates scheduled tasks.</summary>
public interface IScheduledTaskProvider
{
    /// <summary>
    /// Reads all tasks including hidden ones. Hidden tasks matter: a task the
    /// standard UI does not display is a common persistence trick.
    /// </summary>
    IEnumerable<ScheduledTaskRecord> Enumerate(CancellationToken cancellationToken);
}
