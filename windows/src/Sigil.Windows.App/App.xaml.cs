using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Sigil.Windows.App.Services;
using Sigil.Windows.App.ViewModels;
using Sigil.Windows.Core.Abstractions;
using Sigil.Windows.Core.Network;

// Note: NavigationService.RegisterMainWindow() extension needs Window type
using NavigationServiceExtensions = Sigil.Windows.App.Services.NavigationService;

namespace Sigil.Windows.App;

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{
    private Window? _mainWindow;
    private static IServiceProvider? _services;

    public static T GetService<T>() where T : notnull
    {
        return _services?.GetRequiredService<T>()
            ?? throw new InvalidOperationException("Services not initialized");
    }

    public App()
    {
        InitializeComponent();

        // Configure dependency injection
        var services = new ServiceCollection();
        ConfigureServices(services);
        _services = services.BuildServiceProvider();
    }

    /// <summary>
    /// Invoked when the application is launched.
    /// </summary>
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // Create main window with ServerListView
        _mainWindow = new Window
        {
            Title = "Sigil Auth",
            Content = new Views.ServerListView()
        };

        // Register window with navigation service
        var navigationService = _services.GetRequiredService<INavigationService>();
        navigationService.RegisterMainWindow(_mainWindow);

        // Activate main window
        _mainWindow.Activate();

        // Show system tray icon
        var systemTrayService = _services.GetRequiredService<ISystemTrayService>();
        systemTrayService.Show();
        systemTrayService.SetTooltip("Sigil Auth - Ready");

        // TODO: Connect to relay on startup
        // var client = _services.GetRequiredService<IChallengePushService>();
        // await client.ConnectAsync(new Uri("wss://relay.sigilauth.com/ws"));
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Logging
        services.AddLogging(builder =>
        {
            builder.AddDebug();
#if DEBUG
            builder.SetMinimumLevel(LogLevel.Debug);
#else
            builder.SetMinimumLevel(LogLevel.Information);
#endif
        });

        // HTTP client for Sigil API
        services.AddHttpClient<ISigilApiService, SigilApiService>();

        // Core services
        services.AddSingleton<ISecureStorageService, SecureStorageService>();
        services.AddSingleton<IWindowsHelloService, WindowsHelloService>();
        services.AddSingleton<IDeviceKeyService, DeviceKeyService>();
        services.AddSingleton<IChallengeService, ChallengeService>();

        // UI services
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<ISystemTrayService, SystemTrayService>();

        // Legacy services (for compatibility)
        services.AddSingleton<IDeviceKeyProvider, WindowsHelloKeyProvider>();
        services.AddSingleton<IChallengePushService, WebSocketChallengeListener>();

        // ViewModels
        services.AddTransient<PairFlowViewModel>();
        services.AddTransient<ServerListViewModel>();
        services.AddTransient<ApprovalViewModel>();

        // Legacy main window (for testing)
        services.AddTransient<MainWindow>();
    }
}
