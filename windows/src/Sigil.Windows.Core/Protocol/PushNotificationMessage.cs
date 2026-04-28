using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

public sealed class PushNotificationMessage
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("challenge_id")]
    public string? ChallengeId { get; init; }

    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("payload")]
    public string? Payload { get; init; }
}
