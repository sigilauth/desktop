using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.Core.Network;

public interface IChallengePushService : IDisposable
{
    public event EventHandler<PushNotificationReceivedEventArgs>? NotificationReceived;
    public event EventHandler<ConnectionStateChangedEventArgs>? ConnectionStateChanged;

    public Task ConnectAsync(Uri relayUri, CancellationToken cancellationToken = default);
    public Task DisconnectAsync(CancellationToken cancellationToken = default);

    public ConnectionState State { get; }
    public string? Fingerprint { get; }
}

public sealed class PushNotificationReceivedEventArgs : EventArgs
{
    public required PushNotificationMessage Notification { get; init; }
}

public sealed class ConnectionStateChangedEventArgs : EventArgs
{
    public required ConnectionState OldState { get; init; }
    public required ConnectionState NewState { get; init; }
    public string? Error { get; init; }
}
