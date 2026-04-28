namespace Sigil.Windows.App.Models;

/// <summary>
/// Represents a paired server configuration.
/// Displayed in ServerListView with name and pictogram preview.
/// </summary>
public sealed class ServerConfig
{
    /// <summary>
    /// Unique identifier for the server (from /pair/init response).
    /// </summary>
    public required string ServerId { get; init; }

    /// <summary>
    /// Display name for the server (machine name or custom name).
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Server base URL (for API calls).
    /// </summary>
    public required string Url { get; init; }

    /// <summary>
    /// Server public key fingerprint (SHA256 hash, base64-encoded).
    /// Used to lookup trust storage.
    /// </summary>
    public required string Fingerprint { get; init; }

    /// <summary>
    /// Session pictogram derived from server fingerprint.
    /// Displayed as emoji preview in server list row.
    /// </summary>
    public required Pictogram Pictogram { get; init; }

    /// <summary>
    /// Timestamp when server was paired (ISO 8601 format).
    /// </summary>
    public required string PairedAt { get; init; }
}
