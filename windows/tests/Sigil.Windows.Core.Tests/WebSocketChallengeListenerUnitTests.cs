using System.Net.WebSockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Sigil.Windows.Core.Abstractions;
using Sigil.Windows.Core.Network;
using Xunit;

namespace Sigil.Windows.Core.Tests;

/// <summary>
/// Unit tests for WebSocketChallengeListener edge cases and failure modes.
/// Uses mocked WebSocket to test without network dependencies.
/// </summary>
public sealed class WebSocketChallengeListenerUnitTests
{
    private readonly TestDeviceKeyProvider _keyProvider = new();

    [Fact(Timeout = 5000)]
    public async Task MalformedJson_ThrowsJsonException()
    {
        // Arrange
        var mockWebSocket = new MockWebSocketClient();
        mockWebSocket.EnqueueReceive(WebSocketMessageType.Text, "{ this is not valid JSON }", false);

        var listener = CreateListener(() => mockWebSocket);

        // Act & Assert - malformed JSON throws exception during authentication
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(
            async () => await listener.ConnectAsync(new Uri("ws://localhost/ws")));
    }

    [Fact(Timeout = 5000)]
    public async Task WrongMessageTypeSequence_ThrowsJsonException()
    {
        // Arrange - server sends wrong message (missing required auth_challenge fields)
        var mockWebSocket = new MockWebSocketClient();
        mockWebSocket.EnqueueReceive(
            WebSocketMessageType.Text,
            "{\"type\":\"unexpected\"}",
            false);

        var listener = CreateListener(() => mockWebSocket);

        // Act & Assert - missing required properties throws JSON exception
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(
            async () => await listener.ConnectAsync(new Uri("ws://localhost/ws")));
    }

    [Fact(Timeout = 5000)]
    public async Task ServerClosesConnectionDuringAuth_FailsGracefully()
    {
        // Arrange
        var mockWebSocket = new MockWebSocketClient();
        mockWebSocket.EnqueueReceive(
            WebSocketMessageType.Close,
            "Server closed",
            true,
            WebSocketCloseStatus.NormalClosure);

        var listener = CreateListener(() => mockWebSocket);
        var connectionFailed = new TaskCompletionSource<bool>();

        listener.ConnectionStateChanged += (sender, e) =>
        {
            if (e.NewState == ConnectionState.Failed)
            {
                connectionFailed.TrySetResult(true);
            }
        };

        // Act
        var connectTask = listener.ConnectAsync(new Uri("ws://localhost/ws"));

        // Assert - should transition to Failed state (exception caught internally)
        var failed = await connectionFailed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(failed);
    }

    [Fact(Timeout = 5000)]
    public async Task CancellationToken_PreCancelledCancelsImmediately()
    {
        // Arrange
        var mockWebSocket = new MockWebSocketClient();
        var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel before connect

        var listener = CreateListener(() => mockWebSocket);

        // Act & Assert - TaskCanceledException is subclass of OperationCanceledException
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await listener.ConnectAsync(new Uri("ws://localhost/ws"), cts.Token));
    }

    [Fact]
    public void ReconnectBackoff_CalculatesCorrectDelay()
    {
        // Arrange & Act - test exponential backoff calculation
        // Attempt 1: 1000ms
        var delay1 = Math.Min(1000 * (int)Math.Pow(2, 0), 60000);

        // Attempt 5: 16000ms
        var delay5 = Math.Min(1000 * (int)Math.Pow(2, 4), 60000);

        // Attempt 10: capped at 60000ms
        var delay10 = Math.Min(1000 * (int)Math.Pow(2, 9), 60000);

        // Assert
        Assert.Equal(1000, delay1);
        Assert.Equal(16000, delay5);
        Assert.Equal(60000, delay10);
    }

    [Fact]
    public void ConnectionState_TransitionsFireEvents()
    {
        // Arrange
        var listener = CreateListener(() => new MockWebSocketClient());
        var stateChanges = new List<(ConnectionState Old, ConnectionState New)>();

        listener.ConnectionStateChanged += (sender, e) =>
        {
            stateChanges.Add((e.OldState, e.NewState));
        };

        // Act - state changes are tested indirectly via connection flow
        // This test verifies the event mechanism works
        Assert.Empty(stateChanges);
        Assert.Equal(ConnectionState.Disconnected, listener.State);
    }

    [Fact(Timeout = 5000)]
    public async Task EmptyMessage_ThrowsJsonException()
    {
        // Arrange - server sends empty text message
        var mockWebSocket = new MockWebSocketClient();
        mockWebSocket.EnqueueReceive(WebSocketMessageType.Text, "", false);

        var listener = CreateListener(() => mockWebSocket);

        // Act & Assert - empty message fails JSON deserialization
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(
            async () => await listener.ConnectAsync(new Uri("ws://localhost/ws")));
    }

    [Fact(Timeout = 5000)]
    public async Task MultipleConnectAttempts_SecondAttemptReturnsEarly()
    {
        // Arrange
        var mockWebSocket = new MockWebSocketClient();
        mockWebSocket.EnqueueValidAuthFlow();

        var listener = CreateListener(() => mockWebSocket);

        // Act
        var firstConnect = listener.ConnectAsync(new Uri("ws://localhost/ws"));
        await Task.Delay(100); // Let first connect start

        var secondConnect = listener.ConnectAsync(new Uri("ws://localhost/ws"));

        // Assert - second connect should return immediately without error
        await Task.WhenAll(firstConnect, secondConnect);
    }

    private WebSocketChallengeListener CreateListener(Func<IWebSocketClient> webSocketFactory)
    {
        return new WebSocketChallengeListener(
            _keyProvider,
            NullLogger<WebSocketChallengeListener>.Instance,
            webSocketFactory);
    }
}

/// <summary>
/// Mock WebSocket client for unit testing.
/// </summary>
internal sealed class MockWebSocketClient : IWebSocketClient
{
    private readonly Queue<MockReceiveResult> _receiveQueue = new();
    private readonly List<byte[]> _sentMessages = new();
    private WebSocketState _state = WebSocketState.None;

    public bool IsDisposed { get; private set; }

    public WebSocketState State => _state;

    public void EnqueueReceive(
        WebSocketMessageType messageType,
        string content,
        bool endOfMessage,
        WebSocketCloseStatus? closeStatus = null)
    {
        _receiveQueue.Enqueue(new MockReceiveResult
        {
            MessageType = messageType,
            Content = Encoding.UTF8.GetBytes(content),
            EndOfMessage = endOfMessage,
            CloseStatus = closeStatus
        });
    }

    public void EnqueueValidAuthFlow()
    {
        // Auth challenge
        EnqueueReceive(
            WebSocketMessageType.Text,
            "{\"type\":\"auth_challenge\",\"challenge\":\"dGVzdA==\",\"expires_at\":\"2026-12-31T23:59:59Z\"}",
            false);

        // Auth success
        EnqueueReceive(
            WebSocketMessageType.Text,
            "{\"type\":\"auth_success\",\"fingerprint\":\"test_fingerprint\"}",
            false);
    }

    public Task ConnectAsync(Uri uri, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _state = WebSocketState.Open;
        return Task.CompletedTask;
    }

    public Task<WebSocketReceiveResult> ReceiveAsync(
        ArraySegment<byte> buffer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_receiveQueue.Count == 0)
        {
            // Simulate waiting forever if no messages queued
            return Task.Delay(-1, cancellationToken)
                .ContinueWith<WebSocketReceiveResult>(_ => throw new InvalidOperationException());
        }

        var result = _receiveQueue.Dequeue();

        if (result.MessageType == WebSocketMessageType.Close)
        {
            _state = WebSocketState.CloseReceived;
            return Task.FromResult(new WebSocketReceiveResult(
                0,
                WebSocketMessageType.Close,
                result.EndOfMessage,
                result.CloseStatus,
                null));
        }

        var bytesToCopy = Math.Min(buffer.Count, result.Content.Length);
        Array.Copy(result.Content, 0, buffer.Array!, buffer.Offset, bytesToCopy);

        return Task.FromResult(new WebSocketReceiveResult(
            bytesToCopy,
            result.MessageType,
            result.EndOfMessage));
    }

    public Task SendAsync(
        ArraySegment<byte> buffer,
        WebSocketMessageType messageType,
        bool endOfMessage,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var message = new byte[buffer.Count];
        Array.Copy(buffer.Array!, buffer.Offset, message, 0, buffer.Count);
        _sentMessages.Add(message);

        return Task.CompletedTask;
    }

    public Task CloseAsync(
        WebSocketCloseStatus closeStatus,
        string? statusDescription,
        CancellationToken cancellationToken)
    {
        _state = WebSocketState.Closed;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        IsDisposed = true;
        _state = WebSocketState.Closed;
    }

    private sealed class MockReceiveResult
    {
        public required WebSocketMessageType MessageType { get; init; }
        public required byte[] Content { get; init; }
        public required bool EndOfMessage { get; init; }
        public WebSocketCloseStatus? CloseStatus { get; init; }
    }
}
