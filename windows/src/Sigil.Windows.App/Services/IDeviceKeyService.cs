namespace Sigil.Windows.App.Services;

/// <summary>
/// Device ECDSA P-256 key service for signing challenges.
/// Key is stored in Windows CNG key storage (software-backed).
/// </summary>
public interface IDeviceKeyService
{
    /// <summary>
    /// Gets or generates the device ECDSA P-256 keypair.
    /// Key persists in CNG key storage with name "SigilAuth_DeviceKey".
    /// </summary>
    Task<(byte[] PublicKey, string Fingerprint)> GetOrCreateKeyAsync();

    /// <summary>
    /// Signs data with the device private key.
    /// Returns DER-encoded ECDSA signature.
    /// </summary>
    /// <param name="data">Data to sign (e.g., challenge bytes)</param>
    /// <returns>DER-encoded ECDSA signature</returns>
    Task<byte[]> SignAsync(byte[] data);

    /// <summary>
    /// Gets the device fingerprint (SHA256 of public key, base64-encoded).
    /// </summary>
    Task<string> GetFingerprintAsync();
}
