using System.Windows;
using System.IO;

namespace Upuaut.Setup;

public partial class App : Application
{
    private void Application_Startup(object sender, StartupEventArgs e)
    {
        var uninstallMode = e.Args.Any(a => string.Equals(a, "--uninstall", StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(Path.GetFileName(Environment.ProcessPath), "Uninstall.exe", StringComparison.OrdinalIgnoreCase);
        var window = new MainWindow(uninstallMode);
        MainWindow = window;
        window.Show();
    }
}
