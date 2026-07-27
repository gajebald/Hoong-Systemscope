using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Windows;

/// <summary>
/// Resolves Windows shell links through <c>IShellLinkW</c>.
/// </summary>
/// <remarks>
/// The link is loaded and read only. <c>SLGP_RAWPATH</c> is used so the stored
/// path comes back as written, without the shell trying to relocate a target
/// that has moved: a shortcut whose target vanished is itself worth reporting,
/// and silently repointing it would erase the finding.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsShortcutResolver : IShortcutResolver
{
    private const int MaxPath = 260;
    private const uint SlgpRawPath = 4;
    private const int StgmRead = 0;

    /// <inheritdoc />
    public ShortcutTarget? Resolve(string shortcutPath)
    {
        if (string.IsNullOrWhiteSpace(shortcutPath) || !File.Exists(shortcutPath))
        {
            return null;
        }

        object? shellLink = null;

        try
        {
            shellLink = new ShellLink();

            if (shellLink is not IPersistFile persistFile || shellLink is not IShellLinkW link)
            {
                return null;
            }

            persistFile.Load(shortcutPath, StgmRead);

            var path = new StringBuilder(MaxPath);
            link.GetPath(path, path.Capacity, IntPtr.Zero, SlgpRawPath);

            var arguments = new StringBuilder(MaxPath * 4);
            link.GetArguments(arguments, arguments.Capacity);

            var workingDirectory = new StringBuilder(MaxPath);
            link.GetWorkingDirectory(workingDirectory, workingDirectory.Capacity);

            return new ShortcutTarget(
                NullIfBlank(path.ToString()),
                NullIfBlank(arguments.ToString()),
                NullIfBlank(workingDirectory.ToString()));
        }
#pragma warning disable CA1031 // A malformed link must degrade to "unresolved", never fail the scan.
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
        finally
        {
            if (shellLink is not null && Marshal.IsComObject(shellLink))
            {
                Marshal.ReleaseComObject(shellLink);
            }
        }
    }

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    [ComImport]
    [Guid("00021401-0000-0000-C000-000000000046")]
    private sealed class ShellLink
    {
    }

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath(
            [MarshalAs(UnmanagedType.LPWStr)] StringBuilder file,
            int maxPath,
            IntPtr findData,
            uint flags);

        void GetIDList(out IntPtr idList);

        void SetIDList(IntPtr idList);

        void GetDescription([MarshalAs(UnmanagedType.LPWStr)] StringBuilder name, int maxName);

        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string name);

        void GetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int maxPath);

        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);

        void GetArguments([MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int maxArguments);

        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);

        void GetHotKey(out short hotKey);

        void SetHotKey(short hotKey);

        void GetShowCmd(out int showCmd);

        void SetShowCmd(int showCmd);

        void GetIconLocation([MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath, int iconPathLength, out int iconIndex);

        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);

        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string relativePath, int reserved);

        void Resolve(IntPtr window, int flags);

        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string file);
    }

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("0000010B-0000-0000-C000-000000000046")]
    private interface IPersistFile
    {
        void GetClassID(out Guid classId);

        [PreserveSig]
        int IsDirty();

        void Load([MarshalAs(UnmanagedType.LPWStr)] string fileName, int mode);

        void Save([MarshalAs(UnmanagedType.LPWStr)] string? fileName, [MarshalAs(UnmanagedType.Bool)] bool remember);

        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string? fileName);

        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string fileName);
    }
}
