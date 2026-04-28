using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Sigil.Windows.Core.Network;

namespace Sigil.Windows.App;

/// <summary>
/// Main application window.
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly IChallengePushService _client;
    private readonly ILogger<MainWindow> _logger;

    public MainWindow(IChallengePushService client, ILogger<MainWindow> logger)
    {
        _client = client;
        _logger = logger;

        InitializeComponent();

        // Subscribe to connection state changes
        _client.ConnectionStateChanged += OnConnectionStateChanged;
        _client.NotificationReceived += OnNotificationReceived;

        UpdateUI();
    }

    private void OnConnectionStateChanged(object? sender, ConnectionStateChangedEventArgs e)
    {
        // Marshal to UI thread
        DispatcherQueue.TryEnqueue(() =>
        {
            StatusText.Text = e.NewState.ToString();
            FingerprintText.Text = _client.Fingerprint ?? "—";
            UpdateUI();
        });
    }

    private void OnNotificationReceived(object? sender, PushNotificationReceivedEventArgs e)
    {
        _logger.LogInformation("Notification received: {Type}", e.Notification.Type);

        // TODO: Show notification dialog
        // - Parse action context
        // - Show approval prompt
        // - Request Windows Hello verification
        // - Sign challenge
        // - Return response
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ConnectButton.IsEnabled = false;
            StatusText.Text = "Connecting...";

            // TODO: Get relay URL from settings
            await _client.ConnectAsync(new Uri("ws://192.168.0.192:30080/ws"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect");
            StatusText.Text = $"Error: {ex.Message}";
        }
        finally
        {
            UpdateUI();
        }
    }

    private async void DisconnectButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            DisconnectButton.IsEnabled = false;
            await _client.DisconnectAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to disconnect");
        }
        finally
        {
            UpdateUI();
        }
    }

    private void UpdateUI()
    {
        ConnectButton.IsEnabled = _client.State == ConnectionState.Disconnected;
        DisconnectButton.IsEnabled = _client.State == ConnectionState.Connected;
    }
}
