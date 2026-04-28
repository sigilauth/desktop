using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

/// <summary>
/// Response from GET /pair/init.
/// Server sends ephemeral nonce + public key for mutual verification.
/// </summary>
public sealed record PairInitResponse(
    [property: JsonPropertyName("server_id")] string ServerId,
    [property: JsonPropertyName("server_public_key")] string ServerPublicKey,
    [property: JsonPropertyName("server_nonce")] string ServerNonce,
    [property: JsonPropertyName("expires_at")] string ExpiresAt
);

/// <summary>
/// Request payload for POST /pair/complete.
/// Client sends server nonce + own public key + device info.
/// </summary>
public sealed record PairCompleteRequest(
    [property: JsonPropertyName("server_nonce")] string ServerNonce,
    [property: JsonPropertyName("client_public_key")] string ClientPublicKey,
    [property: JsonPropertyName("device_info")] DeviceInfo DeviceInfo
);

/// <summary>
/// Device information sent during pairing.
/// </summary>
public sealed record DeviceInfo(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("platform")] string Platform,
    [property: JsonPropertyName("os_version")] string OsVersion
);

/// <summary>
/// Response from POST /pair/complete.
/// Server confirms pairing with public key + timestamp.
/// </summary>
public sealed record PairCompleteResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("server_public_key")] string ServerPublicKey,
    [property: JsonPropertyName("paired_at")] string PairedAt
);
