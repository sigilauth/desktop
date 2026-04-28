using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Sigil.Windows.App.Services;

/// <summary>
/// Service for posting challenge responses to server.
/// Per OpenAPI spec: POST /respond with { challenge_id, fingerprint, signature }
/// </summary>
public sealed class ChallengeService : IChallengeService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ChallengeService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ChallengeService(
        HttpClient httpClient,
        ILogger<ChallengeService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
    }

    public async Task RespondAsync(
        string serverUrl,
        string challengeId,
        string fingerprint,
        byte[] signature,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var url = $"{serverUrl.TrimEnd('/')}/respond";

            var request = new ChallengeResponse(
                ChallengeId: challengeId,
                Fingerprint: fingerprint,
                Signature: Convert.ToBase64String(signature)
            );

            _logger.LogInformation(
                "POST /respond: challenge_id={ChallengeId}, fingerprint={Fingerprint}",
                challengeId,
                fingerprint.Substring(0, 8));

            var response = await _httpClient.PostAsJsonAsync(
                url,
                request,
                _jsonOptions,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);

                // Try to parse error response
                ErrorResponse? error = null;
                try
                {
                    error = JsonSerializer.Deserialize<ErrorResponse>(errorBody, _jsonOptions);
                }
                catch
                {
                    // Ignore parse errors
                }

                var errorMessage = error?.Error ?? $"HTTP {(int)response.StatusCode}";

                _logger.LogError(
                    "POST /respond failed: status={Status}, error={Error}",
                    response.StatusCode,
                    errorMessage);

                throw new ChallengeServiceException(
                    $"Server returned {response.StatusCode}: {errorMessage}",
                    (int)response.StatusCode);
            }

            _logger.LogInformation("POST /respond succeeded");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error during POST /respond");
            throw new ChallengeServiceException("Network error: " + ex.Message, ex);
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning("POST /respond timed out");
            throw new ChallengeServiceException("Request timed out", ex);
        }
    }

    private sealed record ChallengeResponse(
        string ChallengeId,
        string Fingerprint,
        string Signature);

    private sealed record ErrorResponse(
        string Error);
}

/// <summary>
/// Exception thrown when challenge response fails.
/// </summary>
public sealed class ChallengeServiceException : Exception
{
    public int? StatusCode { get; }

    public ChallengeServiceException(string message)
        : base(message)
    {
    }

    public ChallengeServiceException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ChallengeServiceException(string message, int statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }
}
