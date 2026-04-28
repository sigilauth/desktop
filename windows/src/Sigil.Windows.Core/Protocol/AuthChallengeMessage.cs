using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

public sealed class AuthChallengeMessage
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("challenge")]
    public required string Challenge { get; init; }

    [JsonPropertyName("expires_at")]
    public required string ExpiresAt { get; init; }
}
