using System.Windows;
using HoongSystemScope.App;
using HoongSystemScope.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace HoongSystemScope.Wpf;

/// <summary>
/// Application entry point.
/// </summary>
/// <remarks>
/// The composition root is shared with the console front end: this class does
/// nothing but build the container and show the window. Every decision about
/// which implementation backs which abstraction lives in
/// <see cref="ScanServices"/>.
/// </remarks>
public partial class App : Application
{
    private ServiceProvider? _services;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _services = new ServiceCollection()
            .AddHoongSystemScope(LogLevel.Warning)
            .BuildServiceProvider();

        var window = new MainWindow
        {
            DataContext = _services.GetRequiredService<MainViewModel>(),
        };

        window.Show();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _services?.Dispose();
        base.OnExit(e);
    }
}
