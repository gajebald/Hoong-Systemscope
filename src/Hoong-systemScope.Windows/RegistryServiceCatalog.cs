using System.Runtime.Versioning;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Windows;

/// <summary>
/// Reads the service database out of the registry.
/// </summary>
/// <remarks>
/// <para>
/// The service control manager is the obvious source, but reading
/// <c>HKLM\SYSTEM\CurrentControlSet\Services</c> is the better one here. It
/// needs no service handles, works for a standard user across far more of the
/// database, and returns disabled and never-started services that a live SCM
/// query can miss.
/// </para>
/// <para>
/// It also keeps the tool away from the SCM's write surface entirely. There is
/// no code path from here that could start, stop or reconfigure anything.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class RegistryServiceCatalog : IServiceCatalog
{
    private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";

    private readonly IRegistryReader _registry;

    /// <summary>Creates a catalog over the given registry reader.</summary>
    public RegistryServiceCatalog(IRegistryReader registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
    }

    /// <inheritdoc />
    public IEnumerable<ServiceRecord> Enumerate(CancellationToken cancellationToken)
    {
        using var services = _registry.OpenKey(RegistryHiveKind.LocalMachine, ServicesPath);
        if (services is null)
        {
            yield break;
        }

        foreach (var name in services.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var record = TryRead(services, name);
            if (record is not null)
            {
                yield return record;
            }
        }
    }

    private static ServiceRecord? TryRead(IRegistryKey services, string name)
    {
        IRegistryKey? service = null;

        try
        {
            service = services.OpenSubKey(name);
            if (service is null)
            {
                return null;
            }

            var type = service.GetValue("Type")?.AsInt32();
            var kind = ClassifyKind(type);

            // Entries without a type are configuration containers rather than
            // services; skipping them keeps the report honest.
            if (kind == ServiceKind.Unknown)
            {
                return null;
            }

            string? serviceDll = null;
            using (var parameters = service.OpenSubKey("Parameters"))
            {
                serviceDll = parameters?.GetValue("ServiceDll")?.AsString();
            }

            return new ServiceRecord
            {
                ServiceName = name,
                DisplayName = Localized(service.GetValue("DisplayName")?.AsString()) ?? name,
                Description = Localized(service.GetValue("Description")?.AsString()),
                ImagePath = service.GetValue("ImagePath")?.AsString(),
                Account = service.GetValue("ObjectName")?.AsString(),
                Kind = kind,
                StartMode = ClassifyStart(service.GetValue("Start")?.AsInt32()),
                Group = service.GetValue("Group")?.AsString(),
                ServiceDll = serviceDll,
            };
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return null;
        }
        finally
        {
            service?.Dispose();
        }
    }

    /// <summary>
    /// Drops the <c>@file,-id</c> indirection used for localised strings. The
    /// resource id is noise in a report; the service name is already there.
    /// </summary>
    private static string? Localized(string? value) =>
        value is null || !value.StartsWith('@') ? value : null;

    private static ServiceKind ClassifyKind(int? type) => type switch
    {
        null => ServiceKind.Unknown,

        // SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER.
        1 or 2 or 8 => ServiceKind.Driver,

        // SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS and the
        // interactive variants.
        16 or 32 or 272 or 288 => ServiceKind.Service,

        // SERVICE_USER_OWN_PROCESS and friends.
        _ when (type & 0x50) != 0 => ServiceKind.Service,
        _ => ServiceKind.Unknown,
    };

    private static ServiceStartMode ClassifyStart(int? start) => start switch
    {
        0 => ServiceStartMode.Boot,
        1 => ServiceStartMode.System,
        2 => ServiceStartMode.Automatic,
        3 => ServiceStartMode.Manual,
        4 => ServiceStartMode.Disabled,
        _ => ServiceStartMode.Unknown,
    };
}
