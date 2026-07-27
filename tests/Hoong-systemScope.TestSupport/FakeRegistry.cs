using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.TestSupport;

/// <summary>
/// An in-memory registry tree. Building the collectors against
/// <see cref="IRegistryReader"/> rather than against Microsoft.Win32 is what
/// lets the entire scanning logic be exercised on any build agent.
/// </summary>
public sealed class FakeRegistry : IRegistryReader
{
    private readonly Dictionary<(RegistryHiveKind Hive, RegistryViewKind View, string Path), FakeRegistryKey> _keys =
        new(KeyComparer.Instance);

    private readonly HashSet<(RegistryHiveKind Hive, RegistryViewKind View, string Path)> _denied =
        new(KeyComparer.Instance);

    public bool SupportsWow64Views { get; set; } = true;

    /// <summary>Adds or replaces a key.</summary>
    public FakeRegistryKey AddKey(
        RegistryHiveKind hive,
        string path,
        RegistryViewKind view = RegistryViewKind.Default)
    {
        var key = new FakeRegistryKey(this, hive, view, Normalize(path));
        _keys[(hive, view, Normalize(path))] = key;
        EnsureParents(hive, view, Normalize(path));
        return key;
    }

    /// <summary>Marks a key as existing but unreadable, mimicking a missing privilege.</summary>
    public void DenyAccess(RegistryHiveKind hive, string path, RegistryViewKind view = RegistryViewKind.Default) =>
        _denied.Add((hive, view, Normalize(path)));

    public IRegistryKey? OpenKey(RegistryHiveKind hive, string path, RegistryViewKind view = RegistryViewKind.Default)
    {
        var normalized = Normalize(path);

        if (_denied.Contains((hive, view, normalized)))
        {
            throw new UnauthorizedAccessException($"Access to {hive}\\{path} is denied.");
        }

        return _keys.TryGetValue((hive, view, normalized), out var key) ? key : null;
    }

    internal IReadOnlyList<string> GetSubKeyNames(RegistryHiveKind hive, RegistryViewKind view, string path)
    {
        var prefix = path.Length == 0 ? string.Empty : path + "\\";
        var names = new List<string>();

        foreach (var candidate in _keys.Keys)
        {
            if (candidate.Hive != hive || candidate.View != view)
            {
                continue;
            }

            if (!candidate.Path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                candidate.Path.Length == prefix.Length)
            {
                continue;
            }

            var remainder = candidate.Path[prefix.Length..];
            var separator = remainder.IndexOf('\\', StringComparison.Ordinal);
            var name = separator < 0 ? remainder : remainder[..separator];

            if (name.Length > 0 && !names.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(name);
            }
        }

        names.Sort(StringComparer.OrdinalIgnoreCase);
        return names;
    }

    internal FakeRegistryKey? Find(RegistryHiveKind hive, RegistryViewKind view, string path) =>
        _keys.TryGetValue((hive, view, Normalize(path)), out var key) ? key : null;

    internal bool IsDenied(RegistryHiveKind hive, RegistryViewKind view, string path) =>
        _denied.Contains((hive, view, Normalize(path)));

    private void EnsureParents(RegistryHiveKind hive, RegistryViewKind view, string path)
    {
        var separator = path.LastIndexOf('\\');
        while (separator > 0)
        {
            path = path[..separator];
            if (!_keys.ContainsKey((hive, view, path)))
            {
                _keys[(hive, view, path)] = new FakeRegistryKey(this, hive, view, path);
            }

            separator = path.LastIndexOf('\\');
        }
    }

    private static string Normalize(string path) => path.Trim('\\');

    private sealed class KeyComparer : IEqualityComparer<(RegistryHiveKind Hive, RegistryViewKind View, string Path)>
    {
        public static KeyComparer Instance { get; } = new();

        public bool Equals(
            (RegistryHiveKind Hive, RegistryViewKind View, string Path) x,
            (RegistryHiveKind Hive, RegistryViewKind View, string Path) y) =>
            x.Hive == y.Hive && x.View == y.View &&
            string.Equals(x.Path, y.Path, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((RegistryHiveKind Hive, RegistryViewKind View, string Path) obj) =>
            HashCode.Combine(obj.Hive, obj.View, obj.Path.ToUpperInvariant());
    }
}

/// <summary>A key inside a <see cref="FakeRegistry"/>.</summary>
public sealed class FakeRegistryKey : IRegistryKey
{
    private readonly FakeRegistry _registry;
    private readonly RegistryHiveKind _hive;
    private readonly RegistryViewKind _view;
    private readonly string _path;
    private readonly Dictionary<string, RegistryValue> _values = new(StringComparer.OrdinalIgnoreCase);

    internal FakeRegistryKey(FakeRegistry registry, RegistryHiveKind hive, RegistryViewKind view, string path)
    {
        _registry = registry;
        _hive = hive;
        _view = view;
        _path = path;
    }

    public string Path => $"{_hive}\\{_path}";

    public DateTimeOffset? LastWriteTimeUtc { get; set; }

    /// <summary>Adds a string value and returns the key for chaining.</summary>
    public FakeRegistryKey WithValue(string name, string? value)
    {
        _values[name] = new RegistryValue(name, RegistryValueKind.String, value);
        return this;
    }

    /// <summary>Adds a value of an explicit kind and returns the key for chaining.</summary>
    public FakeRegistryKey WithValue(string name, RegistryValueKind kind, object? value)
    {
        _values[name] = new RegistryValue(name, kind, value);
        return this;
    }

    public IReadOnlyList<string> GetSubKeyNames() => _registry.GetSubKeyNames(_hive, _view, _path);

    public IReadOnlyList<string> GetValueNames() => _values.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();

    public RegistryValue? GetValue(string name) => _values.TryGetValue(name, out var value) ? value : null;

    public IRegistryKey? OpenSubKey(string name)
    {
        var childPath = _path.Length == 0 ? name : $"{_path}\\{name}";

        if (_registry.IsDenied(_hive, _view, childPath))
        {
            throw new UnauthorizedAccessException($"Access to {childPath} is denied.");
        }

        return _registry.Find(_hive, _view, childPath);
    }

    public void Dispose()
    {
        // Nothing to release for the in-memory implementation.
    }
}
