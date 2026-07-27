using HoongSystemScope.Core.Models;
using HoongSystemScope.Collectors.Modules;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Collectors.Tests;

public sealed class ScheduledTaskCollectorTests
{
    [Fact]
    public async Task Emits_one_entry_per_action_with_distinct_identities()
    {
        // A task with two actions must not be able to hide the second one
        // behind the first, and both need their own identity so a baseline
        // comparison can track them separately.
        var harness = new ScanHarness();
        harness.ScheduledTasks.Tasks.Add(new ScheduledTaskRecord
        {
            TaskPath = @"\Vendor\Maintenance",
            Name = "Maintenance",
            IsEnabled = true,
            Principal = "SYSTEM",
            Actions =
            [
                new ScheduledTaskAction("Exec", @"C:\Program Files\Vendor\maint.exe", "/daily"),
                new ScheduledTaskAction("Exec", @"C:\Users\bob\AppData\Local\Temp\extra.exe", null),
            ],
        });

        var entries = await ScanHarness.CollectAsync(new ScheduledTaskCollector(), harness.Build());

        Assert.Equal(2, entries.Count);
        Assert.Equal(2, entries.Select(e => e.Id).Distinct().Count());
        Assert.Contains(entries, e => e.ExecutablePath == @"C:\Users\bob\AppData\Local\Temp\extra.exe");
        Assert.All(entries, e => Assert.Equal(@"\Vendor\Maintenance", e.Location));
    }

    [Fact]
    public async Task Keeps_the_plain_task_name_when_there_is_a_single_action()
    {
        var harness = new ScanHarness();
        harness.ScheduledTasks.Tasks.Add(new ScheduledTaskRecord
        {
            TaskPath = @"\Vendor\Update",
            Name = "Update",
            IsEnabled = true,
            Actions = [new ScheduledTaskAction("Exec", @"C:\upd.exe", null)],
        });

        var entries = await ScanHarness.CollectAsync(new ScheduledTaskCollector(), harness.Build());

        Assert.Equal("Update", Assert.Single(entries).Name);
    }

    [Fact]
    public async Task Carries_the_hidden_flag_and_run_level()
    {
        var harness = new ScanHarness();
        harness.ScheduledTasks.Tasks.Add(new ScheduledTaskRecord
        {
            TaskPath = @"\Odd",
            Name = "Odd",
            IsEnabled = true,
            IsHidden = true,
            RunLevel = "HighestAvailable",
            Principal = "SYSTEM",
            TriggerSummary = "At logon",
            Actions = [new ScheduledTaskAction("Exec", @"C:\Temp\x.exe", null)],
        });

        var entries = await ScanHarness.CollectAsync(new ScheduledTaskCollector(), harness.Build());

        var entry = Assert.Single(entries);
        Assert.Equal("true", entry.Metadata[MetadataKeys.TaskHidden]);
        Assert.Equal("HighestAvailable", entry.Metadata[MetadataKeys.TaskRunLevel]);
        Assert.Equal("At logon", entry.Metadata[MetadataKeys.TaskTriggers]);
    }

    [Fact]
    public async Task Still_reports_a_task_that_has_no_actions()
    {
        var harness = new ScanHarness();
        harness.ScheduledTasks.Tasks.Add(new ScheduledTaskRecord
        {
            TaskPath = @"\Empty",
            Name = "Empty",
            IsEnabled = false,
        });

        var entries = await ScanHarness.CollectAsync(new ScheduledTaskCollector(), harness.Build());

        Assert.Equal("Empty", Assert.Single(entries).Name);
    }
}
