namespace Sigil.Windows.App.Services;

/// <summary>
/// Secure storage for trusted server public keys.
/// Uses Windows Credential Locker (PasswordVault) for encrypted persistence.
/// </summary>
public interface ISecureStorageService
{
    /// <summary>
    /// Stores a trusted server public key.
    /// </summary>
    /// <param name="serverFingerprint">SHA256 fingerprint of server public key (base64)</param>
    /// <param name="serverPublicKey">Server public key (base64-encoded compressed P-256)</param>
    /// <param name="pairedAt">ISO 8601 timestamp of pairing</param>
    void StoreTrustedServer(string serverFingerprint, string serverPublicKey, string pairedAt);

    /// <summary>
    /// Retrieves a trusted server public key by fingerprint.
    /// </summary>
    /// <param name="serverFingerprint">SHA256 fingerprint of server public key (base64)</param>
    /// <returns>Server public key (base64) if found, null otherwise</returns>
    string? GetTrustedServer(string serverFingerprint);

    /// <summary>
    /// Checks if a server is trusted.
    /// </summary>
    /// <param name="serverFingerprint">SHA256 fingerprint of server public key (base64)</param>
    bool IsTrusted(string serverFingerprint);

    /// <summary>
    /// Retrieves all trusted servers.
    /// </summary>
    /// <returns>List of (fingerprint, publicKey, pairedAt) tuples</returns>
    List<(string Fingerprint, string PublicKey, string PairedAt)> GetAllTrustedServers();
}
