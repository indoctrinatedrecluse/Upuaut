using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;

namespace Upuaut.App;

public partial class App : Application
{
    public App()
    {
        Log("App constructor");
        AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
        Exit += (s, e) => Log($"App.Exit event: Code={e.ApplicationExitCode}");
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        Log("App.OnStartup enter");
        base.OnStartup(e);
        Log("App.OnStartup exit");
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Log($"App.OnExit enter: Code={e.ApplicationExitCode}");
        base.OnExit(e);
    }

    private static Assembly? OnAssemblyResolve(object? sender, ResolveEventArgs args)
    {
        var requestedName = new AssemblyName(args.Name);
        if (string.Equals(requestedName.Name, "Microsoft.Windows.SDK.NET", StringComparison.OrdinalIgnoreCase))
        {
            var appDir = AppDomain.CurrentDomain.BaseDirectory;
            var sdkNetPath = Path.Combine(appDir, "Microsoft.Windows.SDK.NET.dll");
            if (File.Exists(sdkNetPath))
            {
                Log($"AssemblyResolve: Redirecting {args.Name} -> {sdkNetPath}");
                return Assembly.LoadFrom(sdkNetPath);
            }
        }
        return null;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log($"DispatcherUnhandledException: {e.Exception}");
        e.Handled = false;
    }

    private void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        Log($"CurrentDomainUnhandledException: {e.ExceptionObject}");
    }

    public static void Log(string msg)
    {
        try
        {
            var logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "upuaut_startup.log");
            File.AppendAllText(logPath, $"[{DateTime.UtcNow:O}] [APP] {msg}\n");
        }
        catch
        {
            // Ignore
        }
    }
}
