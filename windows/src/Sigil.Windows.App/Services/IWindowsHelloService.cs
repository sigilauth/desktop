namespace Sigil.Windows.App.Services;

/// <summary>
/// Windows Hello biometric authentication service.
/// Uses UserConsentVerifier for Touch ID, Face ID, or PIN fallback.
/// </summary>
public interface IWindowsHelloService
{
    /// <summary>
    /// Checks if Windows Hello is available on this device.
    /// </summary>
    Task<bool> IsAvailableAsync();

    /// <summary>
    /// Requests user consent via Windows Hello biometric or PIN.
    /// Shows system biometric prompt with the given message.
    /// </summary>
    /// <param name="message">Prompt message shown to user (e.g., "Approve authentication request")</param>
    /// <returns>True if user verified successfully, false if denied or unavailable</returns>
    Task<bool> VerifyUserAsync(string message);

    /// <summary>
    /// Gets the biometric type available (e.g., "Face", "Fingerprint", "PIN").
    /// </summary>
    Task<string> GetBiometricTypeAsync();
}
