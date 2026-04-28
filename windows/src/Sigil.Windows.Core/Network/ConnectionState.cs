namespace Sigil.Windows.Core.Network;

public enum ConnectionState
{
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
    Failed
}
