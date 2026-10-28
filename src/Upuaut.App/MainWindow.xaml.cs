using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
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
    private readonly DispatcherTimer _titleTimer;
    private int _titleOffset = 0;

    // Full Egyptian uniliteral alphabet, guardian deities, and sacred signs
    private static readonly string[] HieroglyphAlphabet = new[]
    {
        // 25 Uniliteral Phonetic Signs
        "𓄿", "𓇋", "𓇌", "𓂝", "𓅱", "𓃀", "𓊪", "𓆑", "𓅓", "𓈖", "𓂋", "𓉔",
        "𓎛", "𓐍", "𓄡", "𓊃", "𓋴", "𓈙", "𓈎", "𓎡", "𓎼", "𓏏", "𓍿", "𓂧", "𓆓",
        "✦",
        // Sacred Guardians of the Duat
        "𓅱", "𓊪", "𓅱", "𓄿", "𓅱", "𓏏", "✦", // Upuaut (Wepwawet)
        "𓅓", "𓂝", "𓅱", "𓅱", "𓏛", "✦", // Thoth (Djehuty)
        "𓌳", "𓂝", "𓐍", "𓏏", "𓆄", "✦", // Ma'at
        "𓇋", "𓈖", "𓊪", "𓅱", "𓃣", "✦", // Anpu (Anubis)
        "𓋴", "𓈙", "𓏏", "𓏛", "✦", // Seshat
        "𓈎", "𓃀", "𓎛", "𓏏", "✦", // Kebechet
        "𓊃", "𓎡", "𓂋", "𓅓", "✦", // Seker
        // Sacred Cosmic Emblems
        "𓋹", "𓊹", "𓊽", "𓁹", "𓇳", "𓇽", "✦"
    };

    public MainWindow()
    {
        try
        {
            AppLogger.Info("MainWindow", "Entering MainWindow constructor");
            InitializeComponent();
            AppLogger.Info("MainWindow", "InitializeComponent completed");

            // Setup animated native title bar with moving hieroglyphs
            _titleTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(160)
            };
            _titleTimer.Tick += (s, e) => UpdateTitleHieroglyphs();
            _titleTimer.Start();

            Loaded += (s, e) =>
            {
                AppLogger.Info("MainWindow", "MainWindow.Loaded fired — Window is visible on screen");
                // Ensure the window is brought to foreground and activated
                Activate();
                Focus();
            };

            Closing += (s, e) => AppLogger.Info("MainWindow", $"MainWindow.Closing fired (Cancel={e.Cancel})");
            Closed += (s, e) =>
            {
                _titleTimer.Stop();
                AppLogger.Info("MainWindow", "MainWindow.Closed fired");
            };

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

    private void UpdateTitleHieroglyphs()
    {
        try
        {
            const int windowLength = 16;
            var sb = new StringBuilder(windowLength * 3);
            for (int i = 0; i < windowLength; i++)
            {
                int idx = (_titleOffset + i) % HieroglyphAlphabet.Length;
                sb.Append(HieroglyphAlphabet[idx]).Append(' ');
            }
            Title = $"Upuaut — Opener of the Ways │ {sb.ToString().TrimEnd()}";
            _titleOffset = (_titleOffset + 1) % HieroglyphAlphabet.Length;
        }
        catch
        {
            // Suppress fallback if window is disposing
        }
    }
}
