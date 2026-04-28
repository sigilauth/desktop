using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace Sigil.Windows.Core.Crypto;

/// <summary>
/// Session pictogram derivation for SIGIL-CONV-V1 pair handshake.
/// Per api/wire-protocol.md section 4.2.
/// </summary>
public static class SessionPictogram
{
    private const int PoolSize = 192;
    private const int PictogramLength = 6;

    /// <summary>
    /// Derives 6 pictogram indices from server_pub, client_pub, and server_nonce.
    /// Uses Argon2id(m=64MiB, t=10, p=1) for grinding resistance.
    /// </summary>
    /// <param name="serverPublicKey">Server static public key (33 bytes compressed)</param>
    /// <param name="clientPublicKey">Client static public key (33 bytes compressed)</param>
    /// <param name="serverNonce">Server nonce (32 bytes random)</param>
    /// <returns>6 indices in range [0, 191]</returns>
    public static int[] DeriveIndices(
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> clientPublicKey,
        ReadOnlySpan<byte> serverNonce)
    {
        if (serverPublicKey.Length != 33)
        {
            throw new ArgumentException("Server public key must be 33 bytes", nameof(serverPublicKey));
        }

        if (clientPublicKey.Length != 33)
        {
            throw new ArgumentException("Client public key must be 33 bytes", nameof(clientPublicKey));
        }

        if (serverNonce.Length != 32)
        {
            throw new ArgumentException("Server nonce must be 32 bytes", nameof(serverNonce));
        }

        Span<byte> password = stackalloc byte[32];
        ComputePassword(serverPublicKey, clientPublicKey, serverNonce, password);

        var derived = DeriveKey(password);

        var indices = new int[PictogramLength];
        for (int i = 0; i < PictogramLength; i++)
        {
            int wordIndex = (derived[2 * i] << 8) | derived[2 * i + 1];
            indices[i] = wordIndex % PoolSize;
        }

        return indices;
    }

    private static void ComputePassword(
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> clientPublicKey,
        ReadOnlySpan<byte> serverNonce,
        Span<byte> password)
    {
        Span<byte> input = stackalloc byte[33 + 33 + 32];
        serverPublicKey.CopyTo(input);
        clientPublicKey.CopyTo(input.Slice(33));
        serverNonce.CopyTo(input.Slice(66));

        SHA256.HashData(input, password);
    }

    private static byte[] DeriveKey(ReadOnlySpan<byte> password)
    {
        using var argon2 = new Argon2id(password.ToArray())
        {
            Salt = DomainTag.Pair,
            MemorySize = 65536,
            Iterations = 10,
            DegreeOfParallelism = 1
        };

        return argon2.GetBytes(32);
    }
}
