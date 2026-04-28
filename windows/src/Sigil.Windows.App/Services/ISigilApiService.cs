using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.App.Services;

/// <summary>
/// HTTP client for Sigil Auth server API endpoints.
/// </summary>
public interface ISigilApiService
{
    /// <summary>
    /// Initiates pair handshake by fetching server public key + nonce.
    /// GET /pair/init
    /// </summary>
    /// <param name="serverUrl">Base server URL (e.g., https://auth.example.com)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pair init response with server ID, public key, nonce, expiry</returns>
    /// <exception cref="HttpRequestException">Network failure or non-success status code</exception>
    /// <exception cref="TaskCanceledException">Request timeout or cancellation</exception>
    Task<PairInitResponse> InitPairAsync(
        string serverUrl,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes pair handshake by sending confirmation to server.
    /// POST /pair/complete
    /// </summary>
    /// <param name="serverUrl">Base server URL (e.g., https://auth.example.com)</param>
    /// <param name="request">Pair completion request payload</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Pair completion response from server</returns>
    /// <exception cref="HttpRequestException">Network failure or non-success status code</exception>
    /// <exception cref="TaskCanceledException">Request timeout or cancellation</exception>
    Task<PairCompleteResponse> CompletePairAsync(
        string serverUrl,
        PairCompleteRequest request,
        CancellationToken cancellationToken = default);
}
