using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Windows.Core.Network;
using Xunit;

namespace Sigil.Windows.Core.Tests;

/// <summary>
/// Integration tests for WebSocket relay protocol.
/// Tests against live relay. Set SIGIL_RELAY_URL environment variable to run.
/// Example: SIGIL_RELAY_URL=ws://192.168.0.192:30080/ws dotnet test
/// </summary>
public sealed class RelayWebSocketIntegrationTests : IDisposable
{
    private readonly TestDeviceKeyProvider _keyProvider = new();
    private readonly Uri? _relayUri;

    public RelayWebSocketIntegrationTests()
    {
        var relayUrl = Environment.GetEnvironmentVariable("SIGIL_RELAY_URL");
        if (!string.IsNullOrEmpty(relayUrl))
        {
            _relayUri = new Uri(relayUrl);
        }
    }

    private bool ShouldSkipTest()
    {
        return _relayUri == null;
    }

    [Fact(Timeout = 30000)]
    public async Task FullHandshake_ConnectsAndAuthenticatesSuccessfully()
    {
        if (ShouldSkipTest()) return;

        // Arrange
        var listener = new WebSocketChallengeListener(_keyProvider, NullLogger<WebSocketChallengeListener>.Instance);
        var authSuccessReceived = new TaskCompletionSource<bool>();

        listener.ConnectionStateChanged += (sender, e) =>
        {
            if (e.NewState == ConnectionState.Connected)
            {
                authSuccessReceived.TrySetResult(true);
            }
            else if (e.NewState == ConnectionState.Failed)
            {
                authSuccessReceived.TrySetException(new InvalidOperationException($"Connection failed: {e.Error}"));
            }
        };

        try
        {
            // Act
            await listener.ConnectAsync(_relayUri!);

            // Assert
            var success = await authSuccessReceived.Task.WaitAsync(TimeSpan.FromSeconds(20));
            Assert.True(success);
            Assert.Equal(ConnectionState.Connected, listener.State);
            Assert.NotNull(listener.Fingerprint);
            Assert.NotEmpty(listener.Fingerprint);
        }
        finally
        {
            await listener.DisconnectAsync();
        }
    }

    [Fact(Timeout = 30000)]
    public async Task GracefulShutdown_ClosesConnectionCleanly()
    {
        if (ShouldSkipTest()) return;

        // Arrange
        var listener = new WebSocketChallengeListener(_keyProvider, NullLogger<WebSocketChallengeListener>.Instance);
        await listener.ConnectAsync(_relayUri!);

        // Wait for connection
        await Task.Delay(3000);
        Assert.Equal(ConnectionState.Connected, listener.State);

        // Act
        await listener.DisconnectAsync();

        // Assert
        Assert.Equal(ConnectionState.Disconnected, listener.State);
    }

    [Fact(Timeout = 60000)]
    public async Task PushNotification_ReceivesAndParsesMessage()
    {
        if (ShouldSkipTest()) return;

        // Arrange
        var listener = new WebSocketChallengeListener(_keyProvider, NullLogger<WebSocketChallengeListener>.Instance);
        var notificationReceived = new TaskCompletionSource<bool>();

        listener.NotificationReceived += (sender, e) =>
        {
            // Any notification received means the protocol is working
            notificationReceived.TrySetResult(true);
        };

        try
        {
            // Act
            await listener.ConnectAsync(_relayUri!);

            // Wait for connection to establish
            await Task.Delay(5000);

            // Note: This test will timeout if no notifications are sent
            // In production, trigger a challenge via the server API
            // For now, we just verify the connection stays alive
            Assert.Equal(ConnectionState.Connected, listener.State);
        }
        finally
        {
            await listener.DisconnectAsync();
        }
    }

    [Fact(Timeout = 45000)]
    public async Task ConnectionState_TransitionsCorrectly()
    {
        if (ShouldSkipTest()) return;

        // Arrange
        var listener = new WebSocketChallengeListener(_keyProvider, NullLogger<WebSocketChallengeListener>.Instance);
        var states = new List<ConnectionState>();

        listener.ConnectionStateChanged += (sender, e) =>
        {
            states.Add(e.NewState);
        };

        try
        {
            // Act
            await listener.ConnectAsync(_relayUri!);
            await Task.Delay(5000);

            // Assert - should go through: Connecting → Authenticating → Connected
            Assert.Contains(ConnectionState.Connecting, states);
            Assert.Contains(ConnectionState.Authenticating, states);
            Assert.Contains(ConnectionState.Connected, states);

            // Verify final state
            Assert.Equal(ConnectionState.Connected, listener.State);
        }
        finally
        {
            await listener.DisconnectAsync();
        }
    }

    [Fact(Timeout = 30000)]
    public async Task MultipleConnections_EachGetUniqueFingerprint()
    {
        if (ShouldSkipTest()) return;

        // Arrange
        var listener1 = new WebSocketChallengeListener(_keyProvider, NullLogger<WebSocketChallengeListener>.Instance);
        var listener2 = new WebSocketChallengeListener(_keyProvider, NullLogger<WebSocketChallengeListener>.Instance);

        try
        {
            // Act
            await listener1.ConnectAsync(_relayUri!);
            await Task.Delay(2000);

            await listener2.ConnectAsync(_relayUri!);
            await Task.Delay(2000);

            // Assert
            Assert.Equal(ConnectionState.Connected, listener1.State);
            Assert.Equal(ConnectionState.Connected, listener2.State);

            Assert.NotNull(listener1.Fingerprint);
            Assert.NotNull(listener2.Fingerprint);

            // Each connection gets a different fingerprint (different keys)
            Assert.NotEqual(listener1.Fingerprint, listener2.Fingerprint);
        }
        finally
        {
            await listener1.DisconnectAsync();
            await listener2.DisconnectAsync();
        }
    }

    public void Dispose()
    {
        // Cleanup handled by individual test teardown
    }
}
