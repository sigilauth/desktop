using System.Drawing;
using System.Windows.Forms;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;

namespace Sigil.Windows.App.Services;

/// <summary>
/// System tray icon service using System.Windows.Forms.NotifyIcon.
/// Provides background presence + quick actions context menu.
/// </summary>
/// <remarks>
/// Uses System.Windows.Forms.NotifyIcon (classic but reliable).
/// Requires reference: System.Windows.Forms NuGet package.
/// Icon asset: Assets/TrayIcon.ico
/// </remarks>
public sealed class SystemTrayService : ISystemTrayService, IDisposable
{
    private readonly ILogger<SystemTrayService> _logger;
    private readonly INavigationService _navigationService;
    private NotifyIcon? _trayIcon;

    public SystemTrayService(
        ILogger<SystemTrayService> logger,
        INavigationService navigationService)
    {
        _logger = logger;
        _navigationService = navigationService;
    }

    public void Show()
    {
        if (_trayIcon is not null)
        {
            _logger.LogDebug("Tray icon already shown");
            return;
        }

        _logger.LogInformation("Showing system tray icon");

        try
        {
            _trayIcon = new NotifyIcon
            {
                Text = "Sigil Auth",
                Visible = true,
                ContextMenuStrip = BuildContextMenu()
            };

            // Load icon from embedded resource or file
            // TODO: Add Assets/TrayIcon.ico to project
            // _trayIcon.Icon = new Icon("Assets/TrayIcon.ico");

            // Fallback: use default application icon
            _trayIcon.Icon = SystemIcons.Shield;

            // Double-click opens server list
            _trayIcon.DoubleClick += OnTrayIconDoubleClick;

            _logger.LogInformation("System tray icon shown successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to show system tray icon");
        }
    }

    public void Hide()
    {
        if (_trayIcon is null)
        {
            return;
        }

        _logger.LogInformation("Hiding system tray icon");

        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _trayIcon = null;
    }

    public void SetTooltip(string tooltip)
    {
        if (_trayIcon is null)
        {
            _logger.LogWarning("Cannot set tooltip: tray icon not initialized");
            return;
        }

        _logger.LogDebug("Setting tray tooltip: {Tooltip}", tooltip);
        _trayIcon.Text = tooltip;
    }

    public void ShowNotification(string title, string message)
    {
        if (_trayIcon is null)
        {
            _logger.LogWarning("Cannot show notification: tray icon not initialized");
            return;
        }

        _logger.LogInformation("Showing tray notification: {Title}", title);

        _trayIcon.ShowBalloonTip(
            timeout: 5000,
            tipTitle: title,
            tipText: message,
            tipIcon: ToolTipIcon.Info);
    }

    public void Dispose()
    {
        Hide();
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();

        var serversItem = new ToolStripMenuItem("Servers...");
        serversItem.Click += OnServersClicked;
        menu.Items.Add(serversItem);

        menu.Items.Add(new ToolStripSeparator());

        var exitItem = new ToolStripMenuItem("Exit");
        exitItem.Click += OnExitClicked;
        menu.Items.Add(exitItem);

        return menu;
    }

    private void OnTrayIconDoubleClick(object? sender, EventArgs e)
    {
        _logger.LogInformation("Tray icon double-clicked - showing server list");
        _navigationService.ShowServerList();
    }

    private void OnServersClicked(object? sender, EventArgs e)
    {
        _logger.LogInformation("Servers clicked from tray menu");
        _navigationService.ShowServerList();
    }

    private void OnExitClicked(object? sender, EventArgs e)
    {
        _logger.LogInformation("Exit clicked from tray menu");

        // Exit the application
        if (Microsoft.UI.Xaml.Application.Current is App app)
        {
            app.Exit();
        }
    }
}
