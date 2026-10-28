using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FluentUI.AspNetCore.Components;

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

        blazorWebView.Services = services.BuildServiceProvider();
    }
}
