using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Windowing;
using WinRT.Interop;

namespace Sigil.Windows.App.Services;

/// <summary>
/// Navigation service for WinUI 3 window management.
/// Manages window lifecycle and view transitions.
/// </summary>
public sealed class NavigationService : INavigationService
{
    private readonly ILogger<NavigationService> _logger;
    private Window? _mainWindow;

    public NavigationService(ILogger<NavigationService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Registers the main window instance.
    /// Called by App.xaml.cs on startup.
    /// </summary>
    public void RegisterMainWindow(Window mainWindow)
    {
        _mainWindow = mainWindow;
        _logger.LogInformation("Main window registered");
    }

    public void ShowServerList()
    {
        if (_mainWindow is null)
        {
            _logger.LogWarning("Cannot show server list: main window not registered");
            return;
        }

        _logger.LogInformation("Showing server list");

        // Navigate to server list view (if using Frame-based navigation)
        // Or simply activate the main window if ServerListView is the default
        ActivateMainWindow();

        // TODO: If using Frame navigation:
        // var frame = _mainWindow.Content as Frame;
        // frame?.Navigate(typeof(ServerListView));
    }

    public void ShowPairFlow()
    {
        _logger.LogInformation("Showing pair flow");

        // TODO: Implement pair flow window/navigation
        // Option 1: New window
        // var pairWindow = new Window { Content = new PairFlowView() };
        // pairWindow.Activate();
        //
        // Option 2: Navigate in main window
        // var frame = _mainWindow?.Content as Frame;
        // frame?.Navigate(typeof(PairFlowView));

        _logger.LogWarning("ShowPairFlow not yet implemented - needs Frame navigation or separate window");
    }

    public void ShowApproval(
        string serverUrl,
        string serverName,
        string serverId,
        string actionDescription,
        string actionDetails,
        string challengeId,
        string challengeB64,
        string serverPublicKeyB64,
        DateTimeOffset expiresAt)
    {
        _logger.LogInformation(
            "Showing approval for challenge_id={ChallengeId}, server={ServerName}",
            challengeId,
            serverName);

        // TODO: Implement approval window
        // var approvalView = new ApprovalView();
        // var viewModel = approvalView.ViewModel;
        // viewModel.StartApproval(
        //     serverUrl, serverName, serverId,
        //     actionDescription, actionDetails,
        //     challengeId, challengeB64, serverPublicKeyB64,
        //     expiresAt);
        //
        // var approvalWindow = new Window { Content = approvalView };
        // approvalWindow.Activate();

        _logger.LogWarning("ShowApproval not yet implemented - needs separate window or dialog");
    }

    public void ActivateMainWindow()
    {
        if (_mainWindow is null)
        {
            _logger.LogWarning("Cannot activate: main window not registered");
            return;
        }

        _logger.LogDebug("Activating main window");

        try
        {
            // Activate the window
            _mainWindow.Activate();

            // Bring to foreground using Win32 interop
            var hwnd = WindowNative.GetWindowHandle(_mainWindow);
            BringWindowToForeground(hwnd);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to activate main window");
        }
    }

    public void Exit()
    {
        _logger.LogInformation("Exiting application");

        if (Application.Current is App app)
        {
            app.Exit();
        }
    }

    private static void BringWindowToForeground(IntPtr hwnd)
    {
        // Use Win32 API to bring window to foreground
        // Requires: using System.Runtime.InteropServices;

        // [DllImport("user32.dll")]
        // static extern bool SetForegroundWindow(IntPtr hWnd);
        //
        // [DllImport("user32.dll")]
        // static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        //
        // const int SW_RESTORE = 9;
        //
        // ShowWindow(hwnd, SW_RESTORE);
        // SetForegroundWindow(hwnd);

        // Simplified: just call Activate() for now
        // Full implementation would restore minimized window + bring to front
    }
}
