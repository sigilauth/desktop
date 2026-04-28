using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

public sealed class AuthSuccessMessage
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("fingerprint")]
    public required string Fingerprint { get; init; }
}
