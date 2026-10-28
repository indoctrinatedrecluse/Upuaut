using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.FluentUI.AspNetCore.Components;
using Upuaut.Chronicles.Services;
using Upuaut.Core.Diagnostics;
using Upuaut.Core.Interfaces;
using Upuaut.Scout.Services;

namespace Upuaut.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        try
        {
            AppLogger.Info("MainWindow", "Entering MainWindow constructor");
            InitializeComponent();
            AppLogger.Info("MainWindow", "InitializeComponent completed");

            Loaded += (s, e) =>
            {
                AppLogger.Info("MainWindow", "MainWindow.Loaded fired — Window is visible on screen");
                // Ensure the window is brought to foreground and activated
                Activate();
                Focus();
            };

            Closing += (s, e) => AppLogger.Info("MainWindow", $"MainWindow.Closing fired (Cancel={e.Cancel})");
            Closed += (s, e) => AppLogger.Info("MainWindow", "MainWindow.Closed fired");

            // Attach to BlazorWebView lifecycle
            blazorWebView.BlazorWebViewInitialized += (s, e) =>
            {
                AppLogger.Info("WebView", "BlazorWebViewInitialized fired");
                e.WebView.CoreWebView2InitializationCompleted += (w, ev) =>
                {
                    if (ev.IsSuccess)
                    {
                        var browserVer = e.WebView.CoreWebView2?.Environment?.BrowserVersionString ?? "Unknown";
                        AppLogger.Info("WebView", $"CoreWebView2 initialized successfully (Runtime: {browserVer})");
                    }
                    else
                    {
                        AppLogger.Error("WebView", "CoreWebView2 initialization failed", ev.InitializationException);
                    }
                };
            };

            var services = new ServiceCollection();

            // Wire up internal diagnostic logging into Blazor dependency injection
            services.AddLogging(builder =>
            {
                builder.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Debug);
                builder.AddProvider(new AppLoggerProvider());
            });

            services.AddWpfBlazorWebView();
#if DEBUG
            services.AddBlazorWebViewDeveloperTools();
#endif
            services.AddFluentUIComponents();

            // Register Core & Domain Services
            services.AddSingleton<IChroniclesService, WindowsEventLogService>();
            services.AddSingleton<ICaptureEngine, ScoutManager>();
            services.AddSingleton<ScoutManager>(sp => (ScoutManager)sp.GetRequiredService<ICaptureEngine>());

            blazorWebView.Services = services.BuildServiceProvider();
            AppLogger.Info("MainWindow", "blazorWebView.Services successfully configured and assigned");
        }
        catch (Exception ex)
        {
            CrashReporter.GenerateCrashDump(ex, "MainWindow Initialization Failure");
            AppLogger.Fatal("MainWindow", "Fatal error during MainWindow construction", ex);
            throw;
        }
    }
}
