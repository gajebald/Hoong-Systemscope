namespace HoongSystemScope.Core.Abstractions;

/// <summary>The interesting parts of a Windows shell link.</summary>
/// <param name="TargetPath">The file the shortcut points at.</param>
/// <param name="Arguments">Arguments passed to the target.</param>
/// <param name="WorkingDirectory">Working directory of the target.</param>
public sealed record ShortcutTarget(string? TargetPath, string? Arguments, string? WorkingDirectory);

/// <summary>Resolves Windows shell links (<c>.lnk</c>).</summary>
public interface IShortcutResolver
{
    /// <summary>
    /// Resolves a shortcut without following or launching anything, or returns
    /// null when the file is not a readable shell link.
    /// </summary>
    ShortcutTarget? Resolve(string shortcutPath);
}
