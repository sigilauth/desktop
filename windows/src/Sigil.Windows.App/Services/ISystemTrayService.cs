namespace Sigil.Windows.App.Services;

/// <summary>
/// System tray icon service for background presence.
/// Shows NotifyIcon in Windows system tray with flyout menu.
/// </summary>
public interface ISystemTrayService
{
    /// <summary>
    /// Shows the system tray icon.
    /// </summary>
    void Show();

    /// <summary>
    /// Hides the system tray icon.
    /// </summary>
    void Hide();

    /// <summary>
    /// Updates the tray icon tooltip text.
    /// </summary>
    void SetTooltip(string tooltip);

    /// <summary>
    /// Shows a notification balloon from the tray icon.
    /// </summary>
    void ShowNotification(string title, string message);
}
