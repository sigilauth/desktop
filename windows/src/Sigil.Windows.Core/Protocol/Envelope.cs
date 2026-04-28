using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

/// <summary>
/// Request envelope payload (before encryption).
/// Per api/wire-protocol.md section 5.1.
/// </summary>
public sealed record RequestPayload(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("body")] object Body,
    [property: JsonPropertyName("timestamp")] long Timestamp,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("audience")] string Audience);

/// <summary>
/// Response envelope payload (before encryption).
/// Per api/wire-protocol.md section 5.3.
/// </summary>
public sealed record ResponsePayload(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("body")] object Body,
    [property: JsonPropertyName("timestamp")] long Timestamp,
    [property: JsonPropertyName("nonce")] string Nonce);

/// <summary>
/// Inner envelope structure (after signing, before encryption).
/// Per api/wire-protocol.md section 5.1.
/// </summary>
public sealed record InnerEnvelope(
    [property: JsonPropertyName("client_public_key")] string ClientPublicKey,
    [property: JsonPropertyName("payload")] string Payload,
    [property: JsonPropertyName("signature")] string Signature);

/// <summary>
/// Outer envelope (after encryption, wire format).
/// Per api/wire-protocol.md section 5.1.
/// </summary>
public sealed record OuterEnvelope(
    [property: JsonPropertyName("envelope")] string Envelope);

/// <summary>
/// Pair handshake init response (plaintext).
/// Per api/wire-protocol.md section 4.1.
/// </summary>
public sealed record PairInitResponse(
    [property: JsonPropertyName("server_id")] string ServerId,
    [property: JsonPropertyName("server_public_key")] string ServerPublicKey,
    [property: JsonPropertyName("server_nonce")] string ServerNonce,
    [property: JsonPropertyName("expires_at")] string ExpiresAt,
    [property: JsonPropertyName("session_pictogram")] string[] SessionPictogram,
    [property: JsonPropertyName("session_pictogram_speakable")] string SessionPictogramSpeakable);

/// <summary>
/// Pair complete request (plaintext).
/// Per api/wire-protocol.md section 4.5.
/// </summary>
public sealed record PairCompleteRequest(
    [property: JsonPropertyName("server_nonce")] string ServerNonce,
    [property: JsonPropertyName("client_public_key")] string ClientPublicKey,
    [property: JsonPropertyName("device_info")] DeviceInfo DeviceInfo);

/// <summary>
/// Device info for pair completion.
/// </summary>
public sealed record DeviceInfo(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("platform")] string Platform,
    [property: JsonPropertyName("os_version")] string? OsVersion = null);

/// <summary>
/// Pair complete response (plaintext).
/// Per api/wire-protocol.md section 4.5.
/// </summary>
public sealed record PairCompleteResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("server_public_key")] string ServerPublicKey,
    [property: JsonPropertyName("paired_at")] string PairedAt);
