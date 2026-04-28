using System.Text.Json.Serialization;

namespace Sigil.Windows.Core.Protocol;

public sealed class AuthFailureMessage
{
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    [JsonPropertyName("error")]
    public required string Error { get; init; }
}
