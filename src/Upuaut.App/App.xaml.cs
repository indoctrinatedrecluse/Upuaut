using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Upuaut.App;

public partial class App : Application
{
    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        File.WriteAllText("crash.log", e.Exception.ToString());
        MessageBox.Show(e.Exception.ToString(), "Upuaut Error", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    private void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        File.WriteAllText("crash.log", e.ExceptionObject?.ToString() ?? "Unknown crash");
    }
}
