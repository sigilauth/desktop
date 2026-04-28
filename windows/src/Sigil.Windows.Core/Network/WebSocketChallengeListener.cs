using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Sigil.Windows.Core.Abstractions;
using Sigil.Windows.Core.Crypto;
using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.Core.Network;

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(AuthChallengeMessage))]
[JsonSerializable(typeof(AuthResponseMessage))]
[JsonSerializable(typeof(AuthSuccessMessage))]
[JsonSerializable(typeof(AuthFailureMessage))]
[JsonSerializable(typeof(PushNotificationMessage))]
[JsonSerializable(typeof(JsonElement))]
internal sealed partial class WebSocketJsonContext : JsonSerializerContext
{
}

public sealed partial class WebSocketChallengeListener : IChallengePushService
{
    private readonly IDeviceKeyProvider _keyProvider;
    private readonly ILogger<WebSocketChallengeListener> _logger;
    private readonly Func<IWebSocketClient> _webSocketFactory;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    private IWebSocketClient? _webSocket;
    private CancellationTokenSource? _receiveCts;
    private DeviceKeyHandle? _deviceKey;
    private Uri? _relayUri;

    private ConnectionState _state = ConnectionState.Disconnected;
    private string? _fingerprint;
    private int _reconnectAttempts;

    private const int MaxReconnectAttempts = 10;
    private const int BaseReconnectDelayMs = 1000;
    private const int MaxReconnectDelayMs = 60000;

    public event EventHandler<PushNotificationReceivedEventArgs>? NotificationReceived;
    public event EventHandler<ConnectionStateChangedEventArgs>? ConnectionStateChanged;

    public ConnectionState State
    {
        get => _state;
        private set
        {
            var oldState = _state;
            _state = value;
            if (oldState != value)
            {
                ConnectionStateChanged?.Invoke(this, new ConnectionStateChangedEventArgs
                {
                    OldState = oldState,
                    NewState = value
                });
            }
        }
    }

    public string? Fingerprint => _fingerprint;

    public WebSocketChallengeListener(
        IDeviceKeyProvider keyProvider,
        ILogger<WebSocketChallengeListener> logger)
        : this(keyProvider, logger, () => new ClientWebSocketAdapter())
    {
    }

    internal WebSocketChallengeListener(
        IDeviceKeyProvider keyProvider,
        ILogger<WebSocketChallengeListener> logger,
        Func<IWebSocketClient> webSocketFactory)
    {
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _webSocketFactory = webSocketFactory ?? throw new ArgumentNullException(nameof(webSocketFactory));
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Already connected or connecting to {RelayUri}")]
    private partial void LogAlreadyConnected(Uri relayUri);

    [LoggerMessage(Level = LogLevel.Information, Message = "Connected to {RelayUri}")]
    private partial void LogConnected(Uri relayUri);

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to connect to {RelayUri}")]
    private partial void LogConnectionFailed(Exception ex, Uri? relayUri);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Received auth challenge, expires at {ExpiresAt}")]
    private partial void LogAuthChallenge(string expiresAt);

    [LoggerMessage(Level = LogLevel.Information, Message = "Authentication successful, fingerprint: {FingerprintPrefix}...")]
    private partial void LogAuthSuccess(string fingerprintPrefix);

    [LoggerMessage(Level = LogLevel.Information, Message = "WebSocket close received: {Status} {Description}")]
    private partial void LogWebSocketClose(WebSocketCloseStatus? status, string? description);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Receive loop cancelled")]
    private partial void LogReceiveLoopCancelled();

    [LoggerMessage(Level = LogLevel.Error, Message = "WebSocket error in receive loop")]
    private partial void LogWebSocketError(WebSocketException ex);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Received push notification: {Type}")]
    private partial void LogNotificationReceived(string type);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Received null message")]
    private partial void LogNullMessage();

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to parse message: {Json}")]
    private partial void LogJsonParseError(JsonException ex, string json);

    [LoggerMessage(Level = LogLevel.Error, Message = "Max reconnect attempts reached, giving up")]
    private partial void LogMaxReconnectAttempts();

    [LoggerMessage(Level = LogLevel.Information, Message = "Reconnecting in {DelayMs}ms (attempt {Attempt}/{Max})")]
    private partial void LogReconnecting(int delayMs, int attempt, int max);

    public async Task ConnectAsync(Uri relayUri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relayUri);

        if (State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Authenticating)
        {
            LogAlreadyConnected(relayUri);
            return;
        }

        _relayUri = relayUri;
        await ConnectInternalAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _receiveCts?.Cancel();

            if (_webSocket?.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                await _webSocket.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "Client disconnect",
                    cancellationToken).ConfigureAwait(false);
            }

            _webSocket?.Dispose();
            _webSocket = null;
            _receiveCts?.Dispose();
            _receiveCts = null;

            State = ConnectionState.Disconnected;
            _reconnectAttempts = 0;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    public void Dispose()
    {
        DisconnectAsync(CancellationToken.None).GetAwaiter().GetResult();
        _connectionLock.Dispose();
    }

    private async Task ConnectInternalAsync(CancellationToken cancellationToken)
    {
        await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            State = ConnectionState.Connecting;

            _webSocket = _webSocketFactory();
            _receiveCts = new CancellationTokenSource();

            var wsUri = new UriBuilder(_relayUri!)
            {
                Scheme = _relayUri!.Scheme == "https" ? "wss" : "ws"
            }.Uri;

            await _webSocket.ConnectAsync(wsUri, cancellationToken).ConfigureAwait(false);
            LogConnected(wsUri);

            State = ConnectionState.Authenticating;
            await AuthenticateAsync(cancellationToken).ConfigureAwait(false);

            State = ConnectionState.Connected;
            _reconnectAttempts = 0;

            _ = Task.Run(() => ReceiveLoopAsync(_receiveCts.Token), _receiveCts.Token);
        }
        catch (WebSocketException ex)
        {
            LogConnectionFailed(ex, _relayUri);
            State = ConnectionState.Failed;
            await TryReconnectAsync().ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            LogConnectionFailed(ex, _relayUri);
            State = ConnectionState.Failed;
            throw;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    private async Task AuthenticateAsync(CancellationToken cancellationToken)
    {
        var challengeMsg = await ReceiveMessageAsync<AuthChallengeMessage>(cancellationToken).ConfigureAwait(false);
        if (challengeMsg is null || challengeMsg.Type != "auth_challenge")
        {
            throw new InvalidOperationException("Expected auth_challenge message");
        }

        LogAuthChallenge(challengeMsg.ExpiresAt);

        var challengeBytes = Convert.FromBase64String(challengeMsg.Challenge);

        if (_deviceKey is null)
        {
            _deviceKey = await _keyProvider.GenerateKeypairAsync(cancellationToken).ConfigureAwait(false);
        }

        // Apply domain separation per api/domain-separation.md
        // V1 auth signature: tag || challenge_bytes || SHA256(canonical_json(action_context))
        // WebSocket relay auth has no action_context, so use empty {} with fixed SHA256 hash
        var emptyActionHash = Convert.FromHexString("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");

        var taggedPayload = new byte[DomainTag.Auth.Length + challengeBytes.Length + emptyActionHash.Length];
        DomainTag.Auth.CopyTo(taggedPayload, 0);
        challengeBytes.CopyTo(taggedPayload, DomainTag.Auth.Length);
        emptyActionHash.CopyTo(taggedPayload, DomainTag.Auth.Length + challengeBytes.Length);

        var signatureBytes = await _keyProvider.SignAsync(
            _deviceKey.Value,
            taggedPayload,
            cancellationToken).ConfigureAwait(false);

        var publicKeyBase64 = Convert.ToBase64String(_deviceKey.Value.CompressedPublicKey.Span);
        var signatureBase64 = Convert.ToBase64String(signatureBytes);

        var authResponse = new AuthResponseMessage
        {
            Type = "auth_response",
            DevicePublicKey = publicKeyBase64,
            Signature = signatureBase64,
            Timestamp = DateTimeOffset.UtcNow.ToString("O")
        };

        await SendMessageAsync(authResponse, cancellationToken).ConfigureAwait(false);

        var response = await ReceiveMessageAsync<JsonElement>(cancellationToken).ConfigureAwait(false);
        var responseType = response.GetProperty("type").GetString();

        if (responseType == "auth_success")
        {
            _fingerprint = response.GetProperty("fingerprint").GetString();
            if (_fingerprint is not null)
            {
                LogAuthSuccess(_fingerprint[..16]);
            }
        }
        else if (responseType == "auth_failure")
        {
            var error = response.GetProperty("error").GetString();
            throw new InvalidOperationException($"Authentication failed: {error}");
        }
        else
        {
            throw new InvalidOperationException($"Unexpected response type: {responseType}");
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];

        try
        {
            while (!cancellationToken.IsCancellationRequested && _webSocket?.State == WebSocketState.Open)
            {
                var result = await _webSocket.ReceiveAsync(
                    new ArraySegment<byte>(buffer),
                    cancellationToken).ConfigureAwait(false);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    LogWebSocketClose(result.CloseStatus, result.CloseStatusDescription);
                    break;
                }

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    var json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    await HandleMessageAsync(json, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            LogReceiveLoopCancelled();
        }
        catch (WebSocketException ex)
        {
            LogWebSocketError(ex);
        }
        finally
        {
            State = ConnectionState.Disconnected;
            await TryReconnectAsync().ConfigureAwait(false);
        }
    }

    private async Task HandleMessageAsync(string json, CancellationToken cancellationToken)
    {
        try
        {
            var message = JsonSerializer.Deserialize(json, WebSocketJsonContext.Default.PushNotificationMessage);
            if (message is null)
            {
                LogNullMessage();
                return;
            }

            LogNotificationReceived(message.Type);

            NotificationReceived?.Invoke(this, new PushNotificationReceivedEventArgs
            {
                Notification = message
            });
        }
        catch (JsonException ex)
        {
            LogJsonParseError(ex, json);
        }
    }

    private async Task TryReconnectAsync()
    {
        if (_relayUri is null || _reconnectAttempts >= MaxReconnectAttempts)
        {
            LogMaxReconnectAttempts();
            State = ConnectionState.Failed;
            return;
        }

        State = ConnectionState.Reconnecting;
        _reconnectAttempts++;

        var delay = Math.Min(
            BaseReconnectDelayMs * (int)Math.Pow(2, _reconnectAttempts - 1),
            MaxReconnectDelayMs);

        LogReconnecting(delay, _reconnectAttempts, MaxReconnectAttempts);

        await Task.Delay(delay).ConfigureAwait(false);
        await ConnectInternalAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private async Task<T?> ReceiveMessageAsync<T>(CancellationToken cancellationToken)
    {
        if (_webSocket is null)
        {
            throw new InvalidOperationException("WebSocket not connected");
        }

        var buffer = new byte[8192];
        var result = await _webSocket.ReceiveAsync(
            new ArraySegment<byte>(buffer),
            cancellationToken).ConfigureAwait(false);

        if (result.MessageType != WebSocketMessageType.Text)
        {
            throw new InvalidOperationException($"Expected text message, got {result.MessageType}");
        }

        var json = Encoding.UTF8.GetString(buffer, 0, result.Count);

        if (typeof(T) == typeof(AuthChallengeMessage))
        {
            return (T?)(object?)JsonSerializer.Deserialize(json, WebSocketJsonContext.Default.AuthChallengeMessage);
        }
        else if (typeof(T) == typeof(JsonElement))
        {
            return (T?)(object?)JsonSerializer.Deserialize(json, WebSocketJsonContext.Default.JsonElement);
        }

        throw new NotSupportedException($"Type {typeof(T).Name} not supported for deserialization");
    }

    private async Task SendMessageAsync<T>(T message, CancellationToken cancellationToken)
    {
        if (_webSocket is null)
        {
            throw new InvalidOperationException("WebSocket not connected");
        }

        string json;
        if (message is AuthResponseMessage authResponse)
        {
            json = JsonSerializer.Serialize(authResponse, WebSocketJsonContext.Default.AuthResponseMessage);
        }
        else
        {
            throw new NotSupportedException($"Type {typeof(T).Name} not supported for serialization");
        }

        var bytes = Encoding.UTF8.GetBytes(json);

        await _webSocket.SendAsync(
            new ArraySegment<byte>(bytes),
            WebSocketMessageType.Text,
            endOfMessage: true,
            cancellationToken).ConfigureAwait(false);
    }
}
