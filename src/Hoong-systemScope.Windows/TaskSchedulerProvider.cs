using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Xml.Linq;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Windows;

/// <summary>
/// Reads the Windows task scheduler through its COM interface.
/// </summary>
/// <remarks>
/// <para>
/// Every task is requested with the "include hidden" flag. A task the standard
/// UI does not show is precisely the kind that deserves to be in a diagnostic
/// report, and the default enumeration silently omits them.
/// </para>
/// <para>
/// Task definitions are read as XML rather than through the typed action
/// interfaces. The XML is the authoritative form, it exposes every action kind
/// including the ones the typed API models awkwardly, and parsing it needs no
/// further COM interop.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class TaskSchedulerProvider : IScheduledTaskProvider
{
    /// <summary>TASK_ENUM_HIDDEN.</summary>
    private const int IncludeHidden = 1;

    /// <inheritdoc />
    public IEnumerable<ScheduledTaskRecord> Enumerate(CancellationToken cancellationToken)
    {
        object? service = null;

        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null)
            {
                return [];
            }

            service = Activator.CreateInstance(type);
            if (service is not ITaskService taskService)
            {
                return [];
            }

            taskService.Connect();

            var records = new List<ScheduledTaskRecord>();
            Walk(taskService.GetFolder("\\"), records, cancellationToken);
            return records;
        }
#pragma warning disable CA1031 // A scheduler that cannot be reached yields no tasks; it must not fail the scan.
        catch (Exception)
#pragma warning restore CA1031
        {
            return [];
        }
        finally
        {
            if (service is not null && Marshal.IsComObject(service))
            {
                Marshal.ReleaseComObject(service);
            }
        }
    }

    private static void Walk(ITaskFolder folder, List<ScheduledTaskRecord> records, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var tasks = folder.GetTasks(IncludeHidden);

            for (var index = 1; index <= tasks.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var record = TryRead(tasks[index]);
                if (record is not null)
                {
                    records.Add(record);
                }
            }

            var folders = folder.GetFolders(0);

            for (var index = 1; index <= folders.Count; index++)
            {
                Walk(folders[index], records, cancellationToken);
            }
        }
        catch (COMException)
        {
            // A folder the caller may not read is a coverage gap, not a
            // failure. The remaining folders are still worth walking.
        }
    }

    private static ScheduledTaskRecord? TryRead(IRegisteredTask task)
    {
        try
        {
            var xml = task.Xml;
            var document = XDocument.Parse(xml);
            XNamespace ns = document.Root?.GetDefaultNamespace() ?? XNamespace.None;

            var settings = document.Root?.Element(ns + "Settings");
            var registration = document.Root?.Element(ns + "RegistrationInfo");
            var principal = document.Root?.Element(ns + "Principals")?.Element(ns + "Principal");

            return new ScheduledTaskRecord
            {
                TaskPath = task.Path,
                Name = task.Name,
                IsEnabled = task.Enabled,
                IsHidden = ParseBool(settings?.Element(ns + "Hidden")?.Value),
                Principal = principal?.Element(ns + "UserId")?.Value
                            ?? principal?.Element(ns + "GroupId")?.Value,
                RunLevel = principal?.Element(ns + "RunLevel")?.Value,
                Author = registration?.Element(ns + "Author")?.Value,
                Description = registration?.Element(ns + "Description")?.Value,
                TriggerSummary = SummarizeTriggers(document, ns),
                Actions = ReadActions(document, ns),
                RegistrationDateUtc = ParseDate(registration?.Element(ns + "Date")?.Value),
            };
        }
#pragma warning disable CA1031 // One unreadable task must not hide the rest.
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    private static List<ScheduledTaskAction> ReadActions(XDocument document, XNamespace ns)
    {
        var actions = document.Root?.Element(ns + "Actions");
        if (actions is null)
        {
            return [];
        }

        var result = new List<ScheduledTaskAction>();

        foreach (var action in actions.Elements())
        {
            var kind = action.Name.LocalName;

            var path = kind switch
            {
                "Exec" => action.Element(ns + "Command")?.Value,
                "ComHandler" => action.Element(ns + "ClassId")?.Value,
                _ => null,
            };

            var arguments = kind switch
            {
                "Exec" => action.Element(ns + "Arguments")?.Value,
                "ComHandler" => action.Element(ns + "Data")?.Value,
                _ => null,
            };

            result.Add(new ScheduledTaskAction(kind, path, arguments));
        }

        return result;
    }

    private static string? SummarizeTriggers(XDocument document, XNamespace ns)
    {
        var triggers = document.Root?.Element(ns + "Triggers");
        if (triggers is null)
        {
            return null;
        }

        var names = triggers.Elements().Select(t => t.Name.LocalName).ToArray();
        return names.Length == 0 ? null : string.Join(", ", names);
    }

    private static bool? ParseBool(string? value) =>
        bool.TryParse(value, out var parsed) ? parsed : null;

    private static DateTimeOffset? ParseDate(string? value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsed)
            ? parsed.ToUniversalTime()
            : null;

    [ComImport]
    [Guid("2FABA4C7-4DA9-4013-9697-20CC3FD40F85")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface ITaskService
    {
        ITaskFolder GetFolder([MarshalAs(UnmanagedType.BStr)] string path);

        [return: MarshalAs(UnmanagedType.IDispatch)]
        object GetRunningTasks(int flags);

        [return: MarshalAs(UnmanagedType.IDispatch)]
        object NewTask(uint flags);

        void Connect(
            [Optional] object serverName,
            [Optional] object user,
            [Optional] object domain,
            [Optional] object password);
    }

    [ComImport]
    [Guid("8CFAC062-A080-4C15-9A88-AA7C2AF80DFC")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface ITaskFolder
    {
        string Name { [return: MarshalAs(UnmanagedType.BStr)] get; }

        string Path { [return: MarshalAs(UnmanagedType.BStr)] get; }

        ITaskFolder GetFolder([MarshalAs(UnmanagedType.BStr)] string path);

        ITaskFolderCollection GetFolders(int flags);

        ITaskFolder CreateFolder(
            [MarshalAs(UnmanagedType.BStr)] string subFolderName,
            [Optional] object securityDescriptor);

        void DeleteFolder([MarshalAs(UnmanagedType.BStr)] string subFolderName, int flags);

        IRegisteredTask GetTask([MarshalAs(UnmanagedType.BStr)] string path);

        IRegisteredTaskCollection GetTasks(int flags);
    }

    [ComImport]
    [Guid("79184A66-8664-423F-97F1-637356A5D812")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface ITaskFolderCollection
    {
        int Count { get; }

        ITaskFolder this[object index] { get; }
    }

    [ComImport]
    [Guid("86627EB4-42A7-41E4-A4D9-AC33A72F2D52")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IRegisteredTaskCollection
    {
        int Count { get; }

        IRegisteredTask this[object index] { get; }
    }

    [ComImport]
    [Guid("9C86F320-DEE3-4DD1-B972-A303F26B061E")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IRegisteredTask
    {
        string Name { [return: MarshalAs(UnmanagedType.BStr)] get; }

        string Path { [return: MarshalAs(UnmanagedType.BStr)] get; }

        int State { get; }

        bool Enabled { get; set; }

        [return: MarshalAs(UnmanagedType.IDispatch)]
        object Run([Optional] object parameters);

        [return: MarshalAs(UnmanagedType.IDispatch)]
        object RunEx([Optional] object parameters, int flags, int sessionId, [Optional] object user);

        [return: MarshalAs(UnmanagedType.IDispatch)]
        object GetInstances(int flags);

        DateTime LastRunTime { get; }

        int LastTaskResult { get; }

        int NumberOfMissedRuns { get; }

        DateTime NextRunTime { get; }

        object Definition { [return: MarshalAs(UnmanagedType.IDispatch)] get; }

        string Xml { [return: MarshalAs(UnmanagedType.BStr)] get; }
    }
}
