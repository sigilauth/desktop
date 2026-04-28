using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.App.Services;

/// <summary>
/// HTTP client for Sigil Auth server API endpoints.
/// </summary>
public sealed class SigilApiService : ISigilApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<SigilApiService> _logger;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public SigilApiService(HttpClient httpClient, ILogger<SigilApiService> logger)
    {
        _httpClient = httpClient;
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
        _logger = logger;
    }

    public async Task<PairInitResponse> InitPairAsync(
        string serverUrl,
        CancellationToken cancellationToken = default)
    {
        var endpoint = $"{serverUrl.TrimEnd('/')}/pair/init";

        _logger.LogDebug("GET {Endpoint}", endpoint);

        var response = await _httpClient.GetAsync(endpoint, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            _logger.LogError(
                "GET {Endpoint} failed: {StatusCode} {ErrorBody}",
                endpoint,
                response.StatusCode,
                errorBody);

            throw new HttpRequestException(
                $"GET /pair/init failed: {response.StatusCode}");
        }

        var result = await response.Content.ReadFromJsonAsync<PairInitResponse>(
            JsonOptions,
            cancellationToken).ConfigureAwait(false);

        if (result is null)
        {
            throw new InvalidOperationException("Server returned null response");
        }

        _logger.LogInformation(
            "Pair init successful: server_id={ServerId}, expires_at={ExpiresAt}",
            result.ServerId,
            result.ExpiresAt);

        return result;
    }

    public async Task<PairCompleteResponse> CompletePairAsync(
        string serverUrl,
        PairCompleteRequest request,
        CancellationToken cancellationToken = default)
    {
        var endpoint = $"{serverUrl.TrimEnd('/')}/pair/complete";

        _logger.LogDebug("POST {Endpoint}", endpoint);

        var response = await _httpClient.PostAsJsonAsync(
            endpoint,
            request,
            JsonOptions,
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            _logger.LogError(
                "POST {Endpoint} failed: {StatusCode} {ErrorBody}",
                endpoint,
                response.StatusCode,
                errorBody);

            throw new HttpRequestException(
                $"POST /pair/complete failed: {response.StatusCode}");
        }

        var result = await response.Content.ReadFromJsonAsync<PairCompleteResponse>(
            JsonOptions,
            cancellationToken).ConfigureAwait(false);

        if (result is null)
        {
            throw new InvalidOperationException("Server returned null response");
        }

        _logger.LogInformation("Pair complete successful: paired_at={PairedAt}", result.PairedAt);

        return result;
    }
}
