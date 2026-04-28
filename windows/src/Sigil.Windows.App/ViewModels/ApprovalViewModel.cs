using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Sigil.Windows.App.Models;
using Sigil.Windows.App.Services;

namespace Sigil.Windows.App.ViewModels;

/// <summary>
/// ViewModel for out-of-band challenge approval.
/// Displays server info, action details, and biometric approve/deny buttons.
/// </summary>
public sealed partial class ApprovalViewModel : ObservableObject
{
    private readonly ILogger<ApprovalViewModel> _logger;
    private readonly ISecureStorageService _storageService;
    private readonly IWindowsHelloService _windowsHelloService;
    private readonly IDeviceKeyService _deviceKeyService;
    private readonly IChallengeService _challengeService;
    private CancellationTokenSource? _expiryTimerCts;

    [ObservableProperty]
    private string _serverName = string.Empty;

    [ObservableProperty]
    private string _serverId = string.Empty;

    [ObservableProperty]
    private string _actionDescription = string.Empty;

    [ObservableProperty]
    private string _actionDetails = string.Empty;

    [ObservableProperty]
    private string _challengeId = string.Empty;

    [ObservableProperty]
    private string _challengeB64 = string.Empty;

    [ObservableProperty]
    private string _serverPublicKeyB64 = string.Empty;

    [ObservableProperty]
    private string _serverUrl = string.Empty;

    [ObservableProperty]
    private Pictogram? _serverPictogram;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TimeRemainingText))]
    private int _secondsRemaining;

    /// <summary>
    /// Formatted time remaining text.
    /// </summary>
    public string TimeRemainingText
    {
        get
        {
            if (SecondsRemaining >= 60)
            {
                int minutes = SecondsRemaining / 60;
                return $"{minutes} minute{(minutes == 1 ? "" : "s")}";
            }
            else if (SecondsRemaining > 0)
            {
                return $"{SecondsRemaining} seconds";
            }
            else
            {
                return "expired";
            }
        }
    }

    [ObservableProperty]
    private bool _isExpired;

    [ObservableProperty]
    private bool _isApproving;

    [ObservableProperty]
    private bool _isComplete;

    [ObservableProperty]
    private bool _isDenied;

    [ObservableProperty]
    private string? _errorMessage;

    public ApprovalViewModel(
        ILogger<ApprovalViewModel> logger,
        ISecureStorageService storageService,
        IWindowsHelloService windowsHelloService,
        IDeviceKeyService deviceKeyService,
        IChallengeService challengeService)
    {
        _logger = logger;
        _storageService = storageService;
        _windowsHelloService = windowsHelloService;
        _deviceKeyService = deviceKeyService;
        _challengeService = challengeService;
    }

    /// <summary>
    /// Initializes approval flow with challenge data from relay notification.
    /// </summary>
    public void StartApproval(
        string serverUrl,
        string serverName,
        string serverId,
        string actionDescription,
        string actionDetails,
        string challengeId,
        string challengeB64,
        string serverPublicKeyB64,
        DateTimeOffset expiresAt)
    {
        ServerUrl = serverUrl;
        ServerName = serverName;
        ServerId = serverId;
        ActionDescription = actionDescription;
        ActionDetails = actionDetails;
        ChallengeId = challengeId;
        ChallengeB64 = challengeB64;
        ServerPublicKeyB64 = serverPublicKeyB64;

        // Derive pictogram from server public key
        try
        {
            var serverPubKey = Convert.FromBase64String(serverPublicKeyB64);
            var fingerprint = System.Security.Cryptography.SHA256.HashData(serverPubKey);
            ServerPictogram = Models.Pictogram.DeriveFromFingerprint(fingerprint);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to derive server pictogram");
        }

        var ttl = (int)(expiresAt - DateTimeOffset.UtcNow).TotalSeconds;
        SecondsRemaining = Math.Max(0, ttl);

        _expiryTimerCts?.Cancel();
        _expiryTimerCts = new CancellationTokenSource();

        StartCountdownTimer(_expiryTimerCts.Token);

        _logger.LogInformation(
            "Approval flow started: server={ServerId}, action={Action}, expires={Expires}",
            ServerId, ActionDescription, expiresAt);
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
                Deny(); // Auto-deny on expiry
                _logger.LogWarning("Approval expired - auto-denied");
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when user approves or denies
        }
    }

    /// <summary>
    /// Approves the challenge with Windows Hello biometric gate + ECDSA signature.
    /// POSTs signed response to server /respond endpoint.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanApprove))]
    private async Task ApproveAsync(CancellationToken cancellationToken)
    {
        _expiryTimerCts?.Cancel();
        IsApproving = true;
        ErrorMessage = null;

        try
        {
            _logger.LogInformation("User initiated approval with biometric");

            // Step 1: Windows Hello biometric gate
            var verified = await _windowsHelloService.VerifyUserAsync(
                $"Approve {ActionDescription} for {ServerName}");

            if (!verified)
            {
                ErrorMessage = "Biometric verification failed or cancelled.";
                _logger.LogWarning("Windows Hello verification denied by user");
                return;
            }

            // Step 2: Sign challenge with device ECDSA key
            var challengeBytes = Convert.FromBase64String(ChallengeB64);
            var signature = await _deviceKeyService.SignAsync(challengeBytes);
            var fingerprint = await _deviceKeyService.GetFingerprintAsync();

            _logger.LogInformation(
                "Challenge signed: fingerprint={Fingerprint}, sig_len={SigLen}",
                fingerprint.Substring(0, 8),
                signature.Length);

            // Step 3: POST to server /respond endpoint
            await _challengeService.RespondAsync(
                ServerUrl,
                ChallengeId,
                fingerprint,
                signature,
                cancellationToken);

            IsComplete = true;
            _logger.LogInformation("Approval complete: challenge_id={ChallengeId}", ChallengeId);
        }
        catch (TaskCanceledException)
        {
            ErrorMessage = "Request timed out.";
            _logger.LogWarning("Approval request timed out");
        }
        catch (ChallengeServiceException ex)
        {
            ErrorMessage = ex.StatusCode.HasValue
                ? $"Server error ({ex.StatusCode}): {ex.Message}"
                : $"Network error: {ex.Message}";
            _logger.LogError(ex, "Challenge response failed");
        }
        catch (HttpRequestException ex)
        {
            ErrorMessage = $"Network error: {ex.Message}";
            _logger.LogError(ex, "POST /respond failed");
        }
        catch (CryptographicException ex)
        {
            ErrorMessage = "Cryptographic error. Check device key.";
            _logger.LogError(ex, "Signing failed");
        }
        catch (Exception ex)
        {
            ErrorMessage = "Unexpected error. Check logs.";
            _logger.LogError(ex, "Approval failed");
        }
        finally
        {
            IsApproving = false;
        }
    }

    private bool CanApprove() => !IsExpired && !IsApproving && !IsComplete && !IsDenied;

    /// <summary>
    /// Denies the challenge.
    /// </summary>
    [RelayCommand]
    private void Deny()
    {
        _expiryTimerCts?.Cancel();
        IsDenied = true;
        _logger.LogInformation("User denied approval: challenge_id={ChallengeId}", ChallengeId);
    }
}
