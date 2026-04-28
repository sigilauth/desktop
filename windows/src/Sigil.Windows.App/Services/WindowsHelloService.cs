using Microsoft.Extensions.Logging;
using Windows.Security.Credentials.UI;

namespace Sigil.Windows.App.Services;

/// <summary>
/// Windows Hello biometric authentication service.
/// Uses UserConsentVerifier for Touch ID, Face ID, fingerprint, or PIN fallback.
/// </summary>
public sealed class WindowsHelloService : IWindowsHelloService
{
    private readonly ILogger<WindowsHelloService> _logger;

    public WindowsHelloService(ILogger<WindowsHelloService> logger)
    {
        _logger = logger;
    }

    public async Task<bool> IsAvailableAsync()
    {
        try
        {
            var availability = await UserConsentVerifier.CheckAvailabilityAsync();

            bool available = availability == UserConsentVerifierAvailability.Available;

            _logger.LogInformation(
                "Windows Hello availability: {Availability}",
                availability);

            return available;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check Windows Hello availability");
            return false;
        }
    }

    public async Task<bool> VerifyUserAsync(string message)
    {
        try
        {
            _logger.LogInformation("Requesting Windows Hello verification: {Message}", message);

            var result = await UserConsentVerifier.RequestVerificationAsync(message);

            bool verified = result == UserConsentVerificationResult.Verified;

            _logger.LogInformation(
                "Windows Hello verification result: {Result}",
                result);

            return verified;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Windows Hello verification failed");
            return false;
        }
    }

    public async Task<string> GetBiometricTypeAsync()
    {
        try
        {
            var availability = await UserConsentVerifier.CheckAvailabilityAsync();

            return availability switch
            {
                UserConsentVerifierAvailability.Available => "Windows Hello",
                UserConsentVerifierAvailability.DeviceNotPresent => "None",
                UserConsentVerifierAvailability.NotConfiguredForUser => "Not Configured",
                UserConsentVerifierAvailability.DisabledByPolicy => "Disabled by Policy",
                UserConsentVerifierAvailability.DeviceBusy => "Device Busy",
                _ => "Unknown"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get biometric type");
            return "Unknown";
        }
    }
}
