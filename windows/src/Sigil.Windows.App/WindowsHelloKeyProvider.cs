using System.Security.Cryptography;
using Sigil.Windows.Core.Abstractions;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace Sigil.Windows.App;

/// <summary>
/// Device key provider using Windows Hello for hardware-backed keys.
/// Keys are stored in TPM and protected by biometric authentication.
/// </summary>
public sealed class WindowsHelloKeyProvider : IDeviceKeyProvider
{
    private const string KeyCredentialName = "SigilAuthDevice";
    private readonly Dictionary<string, KeyCredential> _credentials = new();

    /// <summary>
    /// Generates an ECDSA P-256 keypair in Windows Hello (TPM-backed).
    /// Prompts for biometric authentication on first use.
    /// </summary>
    public async Task<DeviceKeyHandle> GenerateKeypairAsync(CancellationToken cancellationToken = default)
    {
        // Check if Windows Hello is available
        if (!await KeyCredentialManager.IsSupportedAsync())
        {
            throw new PlatformNotSupportedException(
                "Windows Hello is not available. Ensure TPM 2.0 is enabled and Windows Hello is configured.");
        }

        // Request credential creation (prompts for biometric if not authenticated)
        var result = await KeyCredentialManager.RequestCreateAsync(
            KeyCredentialName,
            KeyCredentialCreationOption.ReplaceExisting);

        if (result.Status != KeyCredentialStatus.Success)
        {
            throw new InvalidOperationException(
                $"Failed to create Windows Hello credential: {result.Status}");
        }

        var credential = result.Credential;
        _credentials[KeyCredentialName] = credential;

        // Retrieve public key
        var publicKeyBuffer = credential.RetrievePublicKey();
        CryptographicBuffer.CopyToByteArray(publicKeyBuffer, out var publicKeyBytes);

        // Convert from CNG BCRYPT_ECCKEY_BLOB format to compressed SEC1 format
        var compressedPublicKey = ConvertToCompressedSec1(publicKeyBytes);

        return new DeviceKeyHandle(KeyCredentialName, compressedPublicKey);
    }

    /// <summary>
    /// Signs payload with stored Windows Hello credential.
    /// Prompts for biometric authentication each time (per protocol requirement).
    /// Returns raw R||S signature (64 bytes, IEEE P1363 format).
    /// </summary>
    public async Task<byte[]> SignAsync(
        DeviceKeyHandle handle,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        // Retrieve credential
        var openResult = await KeyCredentialManager.OpenAsync(handle.KeyName);
        if (openResult.Status != KeyCredentialStatus.Success)
        {
            throw new InvalidOperationException(
                $"Failed to open credential '{handle.KeyName}': {openResult.Status}");
        }

        var credential = openResult.Credential;

        // Hash payload with SHA-256 (protocol uses hashed payloads)
        var hash = SHA256.HashData(payload.Span);
        var hashBuffer = CryptographicBuffer.CreateFromByteArray(hash);

        // Request signature (triggers biometric prompt)
        var signResult = await credential.RequestSignAsync(hashBuffer);
        if (signResult.Status != KeyCredentialStatus.Success)
        {
            throw new InvalidOperationException(
                $"Failed to sign payload: {signResult.Status}");
        }

        // Extract signature bytes
        var signatureBuffer = signResult.Result;
        var signatureBytes = new byte[signatureBuffer.Length];
        CryptographicBuffer.CopyToByteArray(signatureBuffer, out signatureBytes);

        // Windows Hello returns DER-encoded signature; convert to raw R||S
        return ConvertDerToRaw(signatureBytes);
    }

    /// <summary>
    /// Converts CNG BCRYPT_ECCKEY_BLOB public key to compressed SEC1 format.
    /// CNG format: magic (4 bytes) + key length (4 bytes) + X (32 bytes) + Y (32 bytes)
    /// SEC1 compressed: 0x02/0x03 prefix + X (32 bytes)
    /// </summary>
    private static byte[] ConvertToCompressedSec1(byte[] cngPublicKey)
    {
        if (cngPublicKey.Length != 72)
        {
            throw new ArgumentException(
                $"Invalid CNG public key length: {cngPublicKey.Length} (expected 72 bytes)");
        }

        // Extract X and Y coordinates (skip 8-byte header)
        var x = new byte[32];
        var y = new byte[32];
        Array.Copy(cngPublicKey, 8, x, 0, 32);
        Array.Copy(cngPublicKey, 40, y, 0, 32);

        // Compressed format: prefix (0x02 if Y is even, 0x03 if odd) + X
        var compressed = new byte[33];
        compressed[0] = (byte)((y[^1] & 1) == 0 ? 0x02 : 0x03);
        Array.Copy(x, 0, compressed, 1, 32);

        return compressed;
    }

    /// <summary>
    /// Converts DER-encoded ECDSA signature to raw R||S format (IEEE P1363).
    /// DER: SEQUENCE { r INTEGER, s INTEGER }
    /// Raw: R (32 bytes) || S (32 bytes)
    /// </summary>
    private static byte[] ConvertDerToRaw(byte[] derSignature)
    {
        try
        {
            // Parse DER SEQUENCE
            if (derSignature[0] != 0x30)
            {
                throw new CryptographicException("Invalid DER signature: missing SEQUENCE tag");
            }

            int index = 2; // Skip SEQUENCE tag and length

            // Parse R
            if (derSignature[index++] != 0x02)
            {
                throw new CryptographicException("Invalid DER signature: missing INTEGER tag for R");
            }
            int rLength = derSignature[index++];
            var r = ExtractInteger(derSignature, index, rLength);
            index += rLength;

            // Parse S
            if (derSignature[index++] != 0x02)
            {
                throw new CryptographicException("Invalid DER signature: missing INTEGER tag for S");
            }
            int sLength = derSignature[index++];
            var s = ExtractInteger(derSignature, index, sLength);

            // Concatenate R || S (64 bytes total)
            var raw = new byte[64];
            Array.Copy(r, 0, raw, 0, 32);
            Array.Copy(s, 0, raw, 32, 32);

            return raw;
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            throw new CryptographicException("Failed to parse DER signature", ex);
        }
    }

    /// <summary>
    /// Extracts a 32-byte unsigned integer from DER encoding.
    /// Handles leading zero byte for positive integers with high bit set.
    /// </summary>
    private static byte[] ExtractInteger(byte[] der, int offset, int length)
    {
        var result = new byte[32];

        if (length == 32)
        {
            // Exact 32 bytes - copy directly
            Array.Copy(der, offset, result, 0, 32);
        }
        else if (length == 33 && der[offset] == 0x00)
        {
            // 33 bytes with leading zero - skip the zero
            Array.Copy(der, offset + 1, result, 0, 32);
        }
        else if (length < 32)
        {
            // Less than 32 bytes - pad with leading zeros
            Array.Copy(der, offset, result, 32 - length, length);
        }
        else
        {
            throw new CryptographicException(
                $"Invalid DER integer length: {length} (expected 32 or 33 bytes)");
        }

        return result;
    }
}
