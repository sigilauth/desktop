using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

public sealed class AuthResponseMessage
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("device_public_key")]
    public required string DevicePublicKey { get; init; }

    [JsonPropertyName("signature")]
    public required string Signature { get; init; }

    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }
}
