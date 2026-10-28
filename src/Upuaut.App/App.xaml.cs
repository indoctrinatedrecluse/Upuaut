using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using Upuaut.Core.Diagnostics;

namespace Upuaut.App;

public partial class App : Application
{
    public App()
    {
        AppLogger.Info("App", "Upuaut application initializing...");
        
        // Critical WinRT redirection
        AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
        
        // Comprehensive crash & error trapping
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        
        Exit += (s, e) => AppLogger.Info("App", $"Upuaut exited with code: {e.ApplicationExitCode}");
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        AppLogger.Info("App", $"OnStartup begin (Args: {string.Join(" ", e.Args)})");
        base.OnStartup(e);
        AppLogger.Info("App", "OnStartup completed");
    }

    protected override void OnExit(ExitEventArgs e)
    {
        AppLogger.Info("App", $"OnExit begin: Code={e.ApplicationExitCode}");
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
                AppLogger.Info("App", $"AssemblyResolve: Redirecting {args.Name} -> {sdkNetPath}");
                return Assembly.LoadFrom(sdkNetPath);
            }
        }
        return null;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var dumpPath = CrashReporter.GenerateCrashDump(e.Exception, "WPF Dispatcher UI Thread Exception");

        var message = $"A critical UI thread exception occurred:\n\n{e.Exception.Message}\n\n" +
                      $"A diagnostic crash dump was saved to:\n{dumpPath}\n\n" +
                      "Would you like to open the crash reports folder?";

        var result = MessageBox.Show(
            message,
            "Upuaut — Critical Application Error",
            MessageBoxButton.YesNo,
            MessageBoxImage.Error);

        if (result == MessageBoxResult.Yes)
        {
            AppLogger.OpenCrashFolder();
        }

        e.Handled = true;
    }

    private void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            CrashReporter.GenerateCrashDump(ex, $"AppDomain Unhandled (IsTerminating={e.IsTerminating})");
        }
        else
        {
            AppLogger.Fatal("App", $"Non-Exception object thrown in AppDomain: {e.ExceptionObject}");
        }
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        CrashReporter.GenerateCrashDump(e.Exception, "Background TaskScheduler Unobserved Task Exception");
        // Mark as observed so the process doesn't terminate unexpectedly
        e.SetObserved();
    }
}
