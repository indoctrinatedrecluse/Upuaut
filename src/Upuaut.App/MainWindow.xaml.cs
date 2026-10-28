using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FluentUI.AspNetCore.Components;
using Upuaut.Chronicles.Services;
using Upuaut.Core.Interfaces;

namespace Upuaut.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        try
        {
            App.Log("Entering MainWindow constructor");
            InitializeComponent();
            App.Log("InitializeComponent finished");

            Loaded += (s, e) => App.Log("MainWindow.Loaded fired");
            Closing += (s, e) => App.Log($"MainWindow.Closing fired (Cancel={e.Cancel})");
            Closed += (s, e) => App.Log("MainWindow.Closed fired");

            var services = new ServiceCollection();
            services.AddWpfBlazorWebView();
#if DEBUG
            services.AddBlazorWebViewDeveloperTools();
#endif
            services.AddFluentUIComponents();

            // Register Core & Domain Services
            services.AddSingleton<IChroniclesService, WindowsEventLogService>();

            blazorWebView.Services = services.BuildServiceProvider();
            App.Log("blazorWebView.Services successfully assigned");
        }
        catch (Exception ex)
        {
            App.Log($"MainWindow constructor failed: {ex}");
            throw;
        }
    }
}
