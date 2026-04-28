using System.Net.WebSockets;
using Sigil.Windows.Core.Abstractions;

namespace Sigil.Windows.Core.Network;

/// <summary>
/// Adapter wrapping System.Net.WebSockets.ClientWebSocket.
/// </summary>
internal sealed class ClientWebSocketAdapter : IWebSocketClient
{
    private readonly ClientWebSocket _webSocket;

    public ClientWebSocketAdapter()
    {
        _webSocket = new ClientWebSocket();
    }

    public WebSocketState State => _webSocket.State;

    public Task ConnectAsync(Uri uri, CancellationToken cancellationToken)
    {
        return _webSocket.ConnectAsync(uri, cancellationToken);
    }

    public Task<WebSocketReceiveResult> ReceiveAsync(
        ArraySegment<byte> buffer,
        CancellationToken cancellationToken)
    {
        return _webSocket.ReceiveAsync(buffer, cancellationToken);
    }

    public Task SendAsync(
        ArraySegment<byte> buffer,
        WebSocketMessageType messageType,
        bool endOfMessage,
        CancellationToken cancellationToken)
    {
        return _webSocket.SendAsync(buffer, messageType, endOfMessage, cancellationToken);
    }

    public Task CloseAsync(
        WebSocketCloseStatus closeStatus,
        string? statusDescription,
        CancellationToken cancellationToken)
    {
        return _webSocket.CloseAsync(closeStatus, statusDescription, cancellationToken);
    }

    public void Dispose()
    {
        _webSocket.Dispose();
    }
}
