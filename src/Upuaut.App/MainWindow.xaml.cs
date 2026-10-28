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
        InitializeComponent();

        var services = new ServiceCollection();
        services.AddWpfBlazorWebView();
#if DEBUG
        services.AddBlazorWebViewDeveloperTools();
#endif
        services.AddFluentUIComponents();

        // Register Core & Domain Services
        services.AddSingleton<IChroniclesService, WindowsEventLogService>();

        blazorWebView.Services = services.BuildServiceProvider();
    }
}
