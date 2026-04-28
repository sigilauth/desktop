namespace Sigil.Windows.App.Services;

/// <summary>
/// Navigation service for window management and view transitions.
/// Handles showing/hiding windows and navigating between views.
/// </summary>
public interface INavigationService
{
    /// <summary>
    /// Shows the main window with server list.
    /// Activates and brings to foreground if already open.
    /// </summary>
    void ShowServerList();

    /// <summary>
    /// Shows the pairing flow window.
    /// </summary>
    void ShowPairFlow();

    /// <summary>
    /// Shows the approval view with challenge data.
    /// </summary>
    void ShowApproval(
        string serverUrl,
        string serverName,
        string serverId,
        string actionDescription,
        string actionDetails,
        string challengeId,
        string challengeB64,
        string serverPublicKeyB64,
        DateTimeOffset expiresAt);

    /// <summary>
    /// Activates the main window and brings it to foreground.
    /// </summary>
    void ActivateMainWindow();

    /// <summary>
    /// Closes all windows and exits the application.
    /// </summary>
    void Exit();
}
