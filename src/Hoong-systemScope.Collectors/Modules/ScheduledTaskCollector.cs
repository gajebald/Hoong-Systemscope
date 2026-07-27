using System.Globalization;
using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Entries of the Windows task scheduler.
/// </summary>
/// <remarks>
/// A task can run several actions. Each becomes its own entry so that a single
/// harmless-looking task cannot hide a second action behind the first, but the
/// entries keep the task path as their location so they group together in the
/// report.
/// </remarks>
public sealed class ScheduledTaskCollector : CollectorBase
{
    /// <inheritdoc />
    public override string Id => "scheduled-tasks";

    /// <inheritdoc />
    public override string Description => "Scheduled tasks including hidden ones, with their actions and principal.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.ScheduledTask;

    /// <inheritdoc />
    public override bool RequiresElevation => true;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var task in context.ScheduledTasks.Enumerate(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var shared = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                [MetadataKeys.Description] = task.Description,
                [MetadataKeys.TaskAuthor] = task.Author,
                [MetadataKeys.TaskRunLevel] = task.RunLevel,
                [MetadataKeys.TaskTriggers] = task.TriggerSummary,
                [MetadataKeys.TaskActionCount] = task.Actions.Count.ToString(CultureInfo.InvariantCulture),
            };

            if (task.IsHidden is { } hidden)
            {
                shared[MetadataKeys.TaskHidden] = hidden ? "true" : "false";
            }

            if (task.Actions.Count == 0)
            {
                yield return CreateEntry(
                    context,
                    ScanCategory.ScheduledTask,
                    task.Name,
                    task.TaskPath,
                    userName: task.Principal,
                    isEnabled: task.IsEnabled,
                    metadata: shared);
                continue;
            }

            for (var index = 0; index < task.Actions.Count; index++)
            {
                var action = task.Actions[index];
                var metadata = new Dictionary<string, string?>(shared, StringComparer.OrdinalIgnoreCase)
                {
                    ["task.actionKind"] = action.Kind,
                    ["task.actionIndex"] = index.ToString(CultureInfo.InvariantCulture),
                };

                // Several actions on one task each need their own identity,
                // otherwise the second one would overwrite the first in a
                // baseline comparison.
                var name = task.Actions.Count == 1
                    ? task.Name
                    : string.Create(CultureInfo.InvariantCulture, $"{task.Name} [{index}]");

                yield return CreateEntry(
                    context,
                    ScanCategory.ScheduledTask,
                    name,
                    task.TaskPath,
                    explicitExecutablePath: action.Path,
                    explicitArguments: action.Arguments,
                    userName: task.Principal,
                    isEnabled: task.IsEnabled,
                    metadata: metadata);
            }
        }
    }
}
