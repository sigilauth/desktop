using System.Security.Cryptography;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using Sigil.Windows.App.Services;
using Sigil.Windows.Core.Crypto;
using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.App.ViewModels;

/// <summary>
/// ViewModel for SIGIL-CONV-V1 pair handshake flow.
/// Per api/wire-protocol.md section 4.
/// </summary>
public sealed partial class PairFlowViewModel : ObservableObject
{
    private readonly ILogger<PairFlowViewModel> _logger;
    private readonly ISigilApiService _apiService;
    private readonly ISecureStorageService _storageService;
    private CancellationTokenSource? _expiryTimerCts;

    private byte[]? _serverNonce;
    private byte[]? _clientPublicKey;
    private byte[]? _serverPublicKey;

    [ObservableProperty]
    private string _serverUrl = string.Empty;

    [ObservableProperty]
    private string _serverId = string.Empty;

    [ObservableProperty]
    private bool _isInitiating;

    [ObservableProperty]
    private bool _showUrlInput = true;

    [ObservableProperty]
    private bool _showPictogram;

    [ObservableProperty]
    private PictogramEntry[] _sessionPictogram = Array.Empty<PictogramEntry>();

    [ObservableProperty]
    private string _sessionPictogramSpeakable = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TimerText))]
    [NotifyPropertyChangedFor(nameof(TimerForeground))]
    private int _secondsRemaining;

    /// <summary>
    /// Formatted timer text with proper pluralization.
    /// </summary>
    public string TimerText => $"Expires in {SecondsRemaining}s";

    /// <summary>
    /// Timer foreground color (red when ≤5s, default otherwise).
    /// </summary>
    public Brush TimerForeground => SecondsRemaining > 0 && SecondsRemaining <= 5
        ? new SolidColorBrush(Colors.Red)
        : new SolidColorBrush(Colors.Gray);

    [ObservableProperty]
    private bool _isExpired;

    [ObservableProperty]
    private bool _isPending = true;

    [ObservableProperty]
    private bool _isComplete;

    [ObservableProperty]
    private string? _errorMessage;

    public PairFlowViewModel(
        ILogger<PairFlowViewModel> logger,
        ISigilApiService apiService,
        ISecureStorageService storageService,
        IDeviceKeyService deviceKeyService)
    {
        _logger = logger;
        _apiService = apiService;
        _storageService = storageService;
        _deviceKeyService = deviceKeyService;
    }

    private readonly IDeviceKeyService _deviceKeyService;

    /// <summary>
    /// Initiates pair handshake by calling GET /pair/init.
    /// Generates client keypair and transitions to pictogram confirmation.
    /// </summary>
    [RelayCommand]
    public async Task InitiatePairAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
        {
            ErrorMessage = "Server URL is required.";
            return;
        }

        IsInitiating = true;
        ErrorMessage = null;

        try
        {
            _logger.LogInformation("Initiating pair handshake with {ServerUrl}", ServerUrl);

            // Step 1: GET /pair/init
            var initResponse = await _apiService.InitPairAsync(ServerUrl, cancellationToken)
                .ConfigureAwait(false);

            // Step 2: Get or generate client keypair
            var (clientPublicKey, _) = await _deviceKeyService.GetOrCreateKeyAsync()
                .ConfigureAwait(false);

            // Step 3: Decode server public key
            var serverPublicKey = Convert.FromBase64String(initResponse.ServerPublicKey);
            var serverNonce = Convert.FromBase64String(initResponse.ServerNonce);

            // Step 4: Start pictogram flow
            StartPairFlow(ServerUrl, initResponse, clientPublicKey, serverPublicKey, serverNonce);

            // Transition to pictogram view
            ShowUrlInput = false;
            ShowPictogram = true;
        }
        catch (HttpRequestException ex)
        {
            ErrorMessage = $"Network error: {ex.Message}";
            _logger.LogError(ex, "Failed to initiate pair handshake");
        }
        catch (TaskCanceledException)
        {
            ErrorMessage = "Request timed out.";
            _logger.LogWarning("Pair init timed out");
        }
        catch (Exception ex)
        {
            ErrorMessage = "Unexpected error. Check logs.";
            _logger.LogError(ex, "Pair init failed");
        }
        finally
        {
            IsInitiating = false;
        }
    }

    /// <summary>
    /// Starts pictogram confirmation flow with init response data.
    /// Called by InitiatePairAsync after successful GET /pair/init.
    /// </summary>
    private void StartPairFlow(
        string serverUrl,
        PairInitResponse initResponse,
        byte[] clientPublicKey,
        byte[] serverPublicKey,
        byte[] serverNonce)
    {
        ServerUrl = serverUrl;
        ServerId = initResponse.ServerId;

        _clientPublicKey = clientPublicKey;
        _serverPublicKey = serverPublicKey;
        _serverNonce = serverNonce;

        var indices = SessionPictogram.DeriveIndices(serverPublicKey, clientPublicKey, serverNonce);
        SessionPictogram = PictogramPool.GetEntries(indices);
        SessionPictogramSpeakable = PictogramPool.ToSpeakable(SessionPictogram);

        var expiresAt = DateTimeOffset.Parse(initResponse.ExpiresAt);
        var ttl = (int)(expiresAt - DateTimeOffset.UtcNow).TotalSeconds;

        SecondsRemaining = Math.Max(0, ttl);

        _expiryTimerCts?.Cancel();
        _expiryTimerCts = new CancellationTokenSource();

        StartCountdownTimer(_expiryTimerCts.Token);

        _logger.LogInformation(
            "Pair flow started: server={ServerId}, pictogram={Pictogram}, ttl={Ttl}s",
            ServerId, SessionPictogramSpeakable, SecondsRemaining);
    }

    private async void StartCountdownTimer(CancellationToken cancellationToken)
    {
        try
        {
            while (SecondsRemaining > 0 && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(1000, cancellationToken);
                SecondsRemaining--;
            }

            if (SecondsRemaining == 0)
            {
                IsExpired = true;
                IsPending = false;
                CancelPair(); // Auto-deny on expiry (security requirement)
                _logger.LogWarning("Pair handshake expired - auto-denied");
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when user confirms or cancels
        }
    }

    [RelayCommand(CanExecute = nameof(CanConfirmPair))]
    private async Task ConfirmPairAsync(CancellationToken cancellationToken)
    {
        if (_serverNonce is null || _clientPublicKey is null || _serverPublicKey is null)
        {
            ErrorMessage = "Missing pair handshake data. Retry /pair/init.";
            IsPending = false;
            _logger.LogError("ConfirmPairAsync called without required data");
            return;
        }

        _expiryTimerCts?.Cancel();
        IsPending = false;

        try
        {
            _logger.LogInformation("User confirmed pair handshake — calling POST /pair/complete");

            var deviceInfo = new DeviceInfo(
                Name: Environment.MachineName,
                Platform: "Windows",
                OsVersion: Environment.OSVersion.VersionString);

            var request = new PairCompleteRequest(
                ServerNonce: Convert.ToBase64String(_serverNonce),
                ClientPublicKey: Convert.ToBase64String(_clientPublicKey),
                DeviceInfo: deviceInfo);

            var response = await _apiService.CompletePairAsync(
                ServerUrl,
                request,
                cancellationToken).ConfigureAwait(false);

            var serverFingerprint = ComputeFingerprint(_serverPublicKey);
            var serverPubKeyB64 = Convert.ToBase64String(_serverPublicKey);

            _storageService.StoreTrustedServer(
                serverFingerprint,
                serverPubKeyB64,
                response.PairedAt);

            IsComplete = true;

            _logger.LogInformation(
                "Pair complete: server_fingerprint={Fingerprint}, paired_at={PairedAt}",
                serverFingerprint,
                response.PairedAt);
        }
        catch (TaskCanceledException)
        {
            ErrorMessage = "Request timed out. Check network and retry.";
            _logger.LogWarning("Pair complete request timed out");
        }
        catch (HttpRequestException ex)
        {
            var errorMsg = ex.Message.Contains("410") || ex.Message.Contains("HANDSHAKE_EXPIRED")
                ? "Handshake expired. Retry /pair/init."
                : ex.Message.Contains("403") || ex.Message.Contains("NOT_APPROVED")
                    ? "Not yet approved by admin. Wait and retry."
                    : ex.Message.Contains("403") || ex.Message.Contains("CLIENT_PUB_MISMATCH")
                        ? "Client key mismatch. Retry /pair/init."
                        : "Network error. Check connection and retry.";

            ErrorMessage = errorMsg;
            _logger.LogError(ex, "POST /pair/complete failed: {Message}", ex.Message);
        }
        catch (Exception ex)
        {
            ErrorMessage = "Unexpected error. Check logs.";
            _logger.LogError(ex, "Unexpected error during pair complete");
        }
    }

    private static string ComputeFingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return Convert.ToBase64String(hash);
    }

    private bool CanConfirmPair() => IsPending && !IsExpired && SecondsRemaining > 0;

    [RelayCommand]
    private void CancelPair()
    {
        _expiryTimerCts?.Cancel();
        IsPending = false;
        _logger.LogInformation("User cancelled pair handshake");
    }
}
