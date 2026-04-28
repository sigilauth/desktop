using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Sigil.Windows.App.Services;

/// <summary>
/// Device ECDSA P-256 key service using CNG key storage.
/// Key persists in Windows CNG with name "SigilAuth_DeviceKey".
/// </summary>
public sealed class DeviceKeyService : IDeviceKeyService
{
    private const string KeyName = "SigilAuth_DeviceKey";
    private readonly ILogger<DeviceKeyService> _logger;
    private ECDsa? _cachedKey;

    public DeviceKeyService(ILogger<DeviceKeyService> logger)
    {
        _logger = logger;
    }

    public async Task<(byte[] PublicKey, string Fingerprint)> GetOrCreateKeyAsync()
    {
        await Task.CompletedTask; // Async signature for future TPM integration

        try
        {
            if (_cachedKey is null)
            {
                _cachedKey = LoadOrCreateKey();
            }

            var publicKey = _cachedKey.ExportSubjectPublicKeyInfo();
            var fingerprint = ComputeFingerprint(publicKey);

            _logger.LogInformation(
                "Device key loaded/created: fingerprint={Fingerprint}",
                fingerprint.Substring(0, 8));

            return (publicKey, fingerprint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get or create device key");
            throw;
        }
    }

    public async Task<byte[]> SignAsync(byte[] data)
    {
        await Task.CompletedTask; // Async signature for future biometric gate integration

        try
        {
            if (_cachedKey is null)
            {
                _cachedKey = LoadOrCreateKey();
            }

            var signature = _cachedKey.SignData(data, HashAlgorithmName.SHA256);

            _logger.LogInformation("Signed {Bytes} bytes with device key", data.Length);

            return signature;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign data with device key");
            throw;
        }
    }

    public async Task<string> GetFingerprintAsync()
    {
        var (_, fingerprint) = await GetOrCreateKeyAsync();
        return fingerprint;
    }

    private ECDsa LoadOrCreateKey()
    {
        try
        {
            // Try to open existing key from CNG storage
            var cngKey = CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
            var ecdsa = new ECDsaCng(cngKey);

            _logger.LogInformation("Loaded existing device key from CNG storage");
            return ecdsa;
        }
        catch (CryptographicException)
        {
            // Key doesn't exist - create new one
            _logger.LogInformation("Creating new device key in CNG storage");

            var keyParams = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.None, // Never export private key
                KeyUsage = CngKeyUsages.Signing,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                Parameters =
                {
                    new CngProperty("Length", BitConverter.GetBytes(256), CngPropertyOptions.None)
                }
            };

            var cngKey = CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, keyParams);
            var ecdsa = new ECDsaCng(cngKey);

            _logger.LogInformation("Created new device key in CNG storage");
            return ecdsa;
        }
    }

    private static string ComputeFingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return Convert.ToBase64String(hash);
    }
}
