using System.Security.Cryptography;
using Sigil.Windows.Core.Abstractions;

namespace Sigil.Windows.Core.Tests;

/// <summary>
/// In-memory ECDSA P-256 key provider for integration testing.
/// Generates software keys (not hardware-backed) for WebSocket auth protocol tests.
/// </summary>
public sealed class TestDeviceKeyProvider : IDeviceKeyProvider
{
    private readonly Dictionary<string, ECDsa> _keys = new();

    public Task<DeviceKeyHandle> GenerateKeypairAsync(CancellationToken cancellationToken = default)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var compressedKey = CompressPublicKey(ecdsa.ExportParameters(false));
        var keyName = Guid.NewGuid().ToString();

        _keys[keyName] = ecdsa;

        return Task.FromResult(new DeviceKeyHandle(keyName, compressedKey));
    }

    public Task<byte[]> SignAsync(
        DeviceKeyHandle handle,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        if (!_keys.TryGetValue(handle.KeyName, out var ecdsa))
        {
            throw new InvalidOperationException($"Key not found: {handle.KeyName}");
        }

        var hash = SHA256.HashData(payload.Span);

        // Sign with IEEE P1363 format (raw R||S, 64 bytes for P-256)
        var signature = new byte[64];
        if (!ecdsa.TrySignHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out var bytesWritten))
        {
            throw new InvalidOperationException("Failed to sign hash");
        }

        if (bytesWritten != 64)
        {
            throw new InvalidOperationException($"Expected 64-byte signature, got {bytesWritten}");
        }

        return Task.FromResult(signature);
    }

    private static byte[] CompressPublicKey(ECParameters parameters)
    {
        if (parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new InvalidOperationException("Invalid EC parameters");
        }

        var compressed = new byte[33];
        compressed[0] = (byte)(parameters.Q.Y[^1] % 2 == 0 ? 0x02 : 0x03);
        parameters.Q.X.CopyTo(compressed.AsSpan(1));
        return compressed;
    }

}
