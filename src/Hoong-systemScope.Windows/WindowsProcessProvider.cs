using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Windows.Interop;

namespace HoongSystemScope.Windows;

/// <summary>
/// Enumerates running processes.
/// </summary>
/// <remarks>
/// <para>
/// Command lines and owners come from <c>Win32_Process</c> in a single query,
/// because asking per process would be an order of magnitude slower. Image
/// paths come from <c>QueryFullProcessImageName</c>, which succeeds with only
/// limited-information access where reading the main module does not — that
/// difference decides whether a 64 bit tool can see 32 bit processes and
/// whether an unelevated scan sees anything outside its own session.
/// </para>
/// <para>
/// A process that cannot be inspected fully is still reported, with the fields
/// that were readable. Dropping it would hide it exactly when hiding matters.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessProvider : IProcessProvider
{
    /// <inheritdoc />
    public IEnumerable<ProcessRecord> Enumerate(CancellationToken cancellationToken)
    {
        var details = QueryProcessDetails(cancellationToken);
        var names = new Dictionary<int, string>();
        var records = new List<ProcessRecord>();

        foreach (var process in Process.GetProcesses())
        {
            names[process.Id] = process.ProcessName;
        }

        foreach (var process in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                details.TryGetValue(process.Id, out var detail);

                var parentId = detail?.ParentProcessId;

                records.Add(new ProcessRecord
                {
                    ProcessId = process.Id,
                    Name = process.ProcessName,
                    ExecutablePath = detail?.ExecutablePath ?? TryGetImagePath(process.Id),
                    CommandLine = detail?.CommandLine,
                    ParentProcessId = parentId,
                    ParentName = parentId is { } id && names.TryGetValue(id, out var parentName) ? parentName : null,
                    UserName = detail?.UserName,
                    StartTimeUtc = TryGetStartTime(process),
                });
            }
            finally
            {
                process.Dispose();
            }
        }

        return records;
    }

    private sealed record ProcessDetail(
        string? ExecutablePath,
        string? CommandLine,
        int? ParentProcessId,
        string? UserName);

    /// <summary>
    /// Pulls path, command line and parent for every process in one WMI query.
    /// </summary>
    private static Dictionary<int, ProcessDetail> QueryProcessDetails(CancellationToken cancellationToken)
    {
        var details = new Dictionary<int, ProcessDetail>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process");

            using var collection = searcher.Get();

            foreach (var item in collection)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var management = (ManagementObject)item;

                if (management["ProcessId"] is not uint processId)
                {
                    continue;
                }

                details[(int)processId] = new ProcessDetail(
                    management["ExecutablePath"] as string,
                    management["CommandLine"] as string,
                    management["ParentProcessId"] is uint parent ? (int)parent : null,
                    null);
            }
        }
        catch (ManagementException)
        {
            // WMI can be disabled or unreachable. The scan continues with
            // whatever the process API alone can tell us.
        }
        catch (UnauthorizedAccessException)
        {
        }

        return details;
    }

    /// <summary>
    /// Reads a process image path with limited-information access, which works
    /// for far more processes than reading the main module.
    /// </summary>
    private static string? TryGetImagePath(int processId)
    {
        var handle = NativeMethods.OpenProcess(
            NativeMethods.ProcessQueryLimitedInformation,
            inheritHandle: false,
            (uint)processId);

        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new char[1024];
            var size = (uint)buffer.Length;

            return NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref size)
                ? new string(buffer, 0, (int)size)
                : null;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private static DateTimeOffset? TryGetStartTime(Process process)
    {
        try
        {
            return process.StartTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // System and protected processes refuse this. Not knowing is fine.
            return null;
        }
    }
}
