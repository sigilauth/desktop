namespace Sigil.Windows.App.Services;

/// <summary>
/// Service for posting challenge responses to server.
/// Per OpenAPI spec: POST /respond
/// </summary>
public interface IChallengeService
{
    /// <summary>
    /// Posts signed challenge response to server.
    /// </summary>
    /// <param name="serverUrl">Server base URL (e.g., "https://auth.example.com")</param>
    /// <param name="challengeId">Challenge ID from notification</param>
    /// <param name="fingerprint">Device fingerprint (SHA256 of public key, base64)</param>
    /// <param name="signature">ECDSA signature of challenge bytes (DER-encoded, base64)</param>
    Task RespondAsync(
        string serverUrl,
        string challengeId,
        string fingerprint,
        byte[] signature,
        CancellationToken cancellationToken = default);
}
