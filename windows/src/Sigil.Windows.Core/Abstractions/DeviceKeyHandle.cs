namespace Sigil.Windows.Core.Abstractions;

/// <summary>
/// Opaque handle to a device keypair.
/// For integration tests, this wraps an in-memory ECDSA key.
/// For production, this wraps a TPM/Secure Enclave key handle.
/// </summary>
public readonly record struct DeviceKeyHandle
{
    public string KeyName { get; }
    public ReadOnlyMemory<byte> CompressedPublicKey { get; }

    public DeviceKeyHandle(string keyName, ReadOnlyMemory<byte> compressedPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyName);
        if (compressedPublicKey.IsEmpty)
        {
            throw new ArgumentException("Public key must not be empty.", nameof(compressedPublicKey));
        }

        KeyName = keyName;
        CompressedPublicKey = compressedPublicKey;
    }
}
