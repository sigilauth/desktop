using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Windows.Security.Credentials;

namespace Sigil.Windows.App.Services;

/// <summary>
/// Secure storage for trusted server public keys using Windows Credential Locker.
/// </summary>
public sealed class SecureStorageService : ISecureStorageService
{
    private const string ResourcePrefix = "SigilAuth_TrustedServer_";
    private readonly PasswordVault _vault;
    private readonly ILogger<SecureStorageService> _logger;

    public SecureStorageService(ILogger<SecureStorageService> logger)
    {
        _vault = new PasswordVault();
        _logger = logger;
    }

    public void StoreTrustedServer(string serverFingerprint, string serverPublicKey, string pairedAt)
    {
        var resourceName = ResourcePrefix + serverFingerprint;

        try
        {
            // Remove existing credential if present
            try
            {
                var existing = _vault.Retrieve(resourceName, "server_public_key");
                _vault.Remove(existing);
            }
            catch (Exception)
            {
                // No existing credential — expected on first store
            }

            // Store: resource=fingerprint, username=fixed, password=pubkey|timestamp
            var credential = new PasswordCredential(
                resourceName,
                "server_public_key",
                $"{serverPublicKey}|{pairedAt}");

            _vault.Add(credential);

            _logger.LogInformation(
                "Stored trusted server: fingerprint={Fingerprint}",
                serverFingerprint);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to store trusted server: fingerprint={Fingerprint}",
                serverFingerprint);
            throw;
        }
    }

    public string? GetTrustedServer(string serverFingerprint)
    {
        var resourceName = ResourcePrefix + serverFingerprint;

        try
        {
            var credential = _vault.Retrieve(resourceName, "server_public_key");
            credential.RetrievePassword();

            var parts = credential.Password.Split('|');
            return parts.Length > 0 ? parts[0] : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public bool IsTrusted(string serverFingerprint)
    {
        return GetTrustedServer(serverFingerprint) is not null;
    }

    public List<(string Fingerprint, string PublicKey, string PairedAt)> GetAllTrustedServers()
    {
        var servers = new List<(string, string, string)>();

        try
        {
            var credentials = _vault.RetrieveAll();

            foreach (var credential in credentials)
            {
                // Filter for SigilAuth trusted servers only
                if (!credential.Resource.StartsWith(ResourcePrefix))
                {
                    continue;
                }

                try
                {
                    credential.RetrievePassword();

                    var parts = credential.Password.Split('|');
                    if (parts.Length == 2)
                    {
                        var fingerprint = credential.Resource.Substring(ResourcePrefix.Length);
                        var publicKey = parts[0];
                        var pairedAt = parts[1];

                        servers.Add((fingerprint, publicKey, pairedAt));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(
                        ex,
                        "Failed to retrieve credential: resource={Resource}",
                        credential.Resource);
                }
            }

            _logger.LogInformation("Retrieved {Count} trusted servers", servers.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve all credentials from PasswordVault");
        }

        return servers;
    }
}
