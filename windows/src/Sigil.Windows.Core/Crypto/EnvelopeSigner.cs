using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.Core.Crypto;

/// <summary>
/// Sign-then-encrypt envelope construction for SIGIL-CONV-V1 wire protocol.
/// Per api/wire-protocol.md sections 5.1 (request) and 5.3 (response).
/// </summary>
[RequiresUnreferencedCode("EnvelopeSigner uses CanonicalJson which requires reflection-based serialization")]
[RequiresDynamicCode("EnvelopeSigner requires runtime code generation for JSON serialization")]
public static class EnvelopeSigner
{
    /// <summary>
    /// Nonce store for replay protection (5-min TTL per spec §6.1).
    /// Maps nonce → timestamp when first seen.
    /// </summary>
    private static readonly ConcurrentDictionary<string, DateTimeOffset> NonceStore = new();

    /// <summary>
    /// Creates a signed and encrypted request envelope.
    /// Flow: canonicalize → sign → encrypt → base64
    /// </summary>
    /// <param name="payload">Request payload (action, body, timestamp, nonce, audience)</param>
    /// <param name="clientPrivateKey">Client's ECDSA P-256 private key</param>
    /// <param name="clientPublicKey">Client's compressed public key (33 bytes)</param>
    /// <param name="serverPublicKey">Server's compressed public key (33 bytes)</param>
    /// <returns>Outer envelope ready for wire transmission</returns>
    public static OuterEnvelope SignAndEncryptRequest(
        RequestPayload payload,
        ECDsa clientPrivateKey,
        byte[] clientPublicKey,
        byte[] serverPublicKey)
    {
        var canonicalPayload = CanonicalJson.Serialize(payload);

        var signature = EcdsaSign.Sign(clientPrivateKey, Encoding.UTF8.GetBytes(canonicalPayload), DomainTag.Conv);

        var innerEnvelope = new InnerEnvelope(
            ClientPublicKey: Convert.ToBase64String(clientPublicKey),
            Payload: canonicalPayload,
            Signature: Convert.ToBase64String(signature));

        var innerJson = CanonicalJson.Serialize(innerEnvelope);

        var outerCiphertext = Ecies.Encrypt(serverPublicKey, Encoding.UTF8.GetBytes(innerJson));

        return new OuterEnvelope(Envelope: Convert.ToBase64String(outerCiphertext));
    }

    /// <summary>
    /// Decrypts and verifies a response envelope.
    /// Flow: base64 decode → decrypt → verify signature → parse
    /// </summary>
    /// <param name="envelope">Encrypted response from server</param>
    /// <param name="clientPrivateKey">Client's ECDSA P-256 private key (for decryption)</param>
    /// <param name="serverPublicKey">Server's compressed public key (33 bytes, for signature verification)</param>
    /// <returns>Verified response payload</returns>
    public static ResponsePayload DecryptAndVerifyResponse(
        OuterEnvelope envelope,
        ECDsa clientPrivateKey,
        byte[] serverPublicKey)
    {
        var outerCiphertext = Convert.FromBase64String(envelope.Envelope);

#pragma warning disable CS0618 // Type or member is obsolete - EnvelopeSigner uses software path internally
        var innerJson = Ecies.Decrypt(clientPrivateKey, outerCiphertext);
#pragma warning restore CS0618
        var innerJsonString = Encoding.UTF8.GetString(innerJson);

        var innerEnvelope = JsonSerializer.Deserialize<InnerEnvelope>(innerJsonString)
            ?? throw new InvalidOperationException("Failed to deserialize inner envelope");

        var serverPubKeyFromEnvelope = Convert.FromBase64String(innerEnvelope.ClientPublicKey);
        if (!serverPubKeyFromEnvelope.AsSpan().SequenceEqual(serverPublicKey))
        {
            throw new CryptographicException("Server public key mismatch");
        }

        var signature = Convert.FromBase64String(innerEnvelope.Signature);

        if (!VerifySignature(serverPublicKey, Encoding.UTF8.GetBytes(innerEnvelope.Payload), signature, DomainTag.Conv))
        {
            throw new CryptographicException("Invalid server signature");
        }

        var responsePayload = JsonSerializer.Deserialize<ResponsePayload>(innerEnvelope.Payload)
            ?? throw new InvalidOperationException("Failed to deserialize response payload");

        // Replay protection per spec §6.1 (SIG-2026-RAVEN-P9)
        ValidateReplayProtection(responsePayload);

        return responsePayload;
    }

    /// <summary>
    /// Verifies ECDSA signature with domain separation.
    /// </summary>
    private static bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature, byte[] domain)
    {
        if (signature.Length != 64)
        {
            return false;
        }

        var curveOrder = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        var halfN = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            halfN[i] = (byte)((curveOrder[i] >> 1) | ((i > 0 && (curveOrder[i - 1] & 1) == 1) ? 0x80 : 0));
        }

        var s = signature.AsSpan(32, 32);
        if (CompareBytes(s, halfN) > 0)
        {
            return false;
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(ExportSpkiFromCompressed(publicKey), out _);

        Span<byte> tagged = stackalloc byte[domain.Length + message.Length];
        domain.CopyTo(tagged);
        message.CopyTo(tagged.Slice(domain.Length));

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(tagged, hash);

        return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static int CompareBytes(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    private static byte[] ExportSpkiFromCompressed(byte[] compressed)
    {
        if (compressed.Length != 33)
        {
            throw new ArgumentException("Compressed public key must be 33 bytes");
        }

        var spki = new byte[91];

        spki[0] = 0x30;
        spki[1] = 89;
        spki[2] = 0x30;
        spki[3] = 19;
        spki[4] = 0x06;
        spki[5] = 7;
        spki[6] = 0x2A;
        spki[7] = 0x86;
        spki[8] = 0x48;
        spki[9] = 0xCE;
        spki[10] = 0x3D;
        spki[11] = 0x02;
        spki[12] = 0x01;
        spki[13] = 0x06;
        spki[14] = 8;
        spki[15] = 0x2A;
        spki[16] = 0x86;
        spki[17] = 0x48;
        spki[18] = 0xCE;
        spki[19] = 0x3D;
        spki[20] = 0x03;
        spki[21] = 0x01;
        spki[22] = 0x07;
        spki[23] = 0x03;
        spki[24] = 66;
        spki[25] = 0x00;

        compressed.CopyTo(spki, 26);

        return spki;
    }

    /// <summary>
    /// Validates replay protection (timestamp + nonce) per spec §6.1.
    /// </summary>
    /// <param name="payload">Response payload to validate</param>
    /// <exception cref="CryptographicException">Thrown on replay protection violation</exception>
    private static void ValidateReplayProtection(ResponsePayload payload)
    {
        // Timestamp validation (300s window per spec §6.1)
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - payload.Timestamp) > 300)
        {
            throw new CryptographicException("TIMESTAMP_EXPIRED");
        }

        // Nonce uniqueness check (client MUST track per spec §5.4 SIG-2026-FINDING-2)
        if (!NonceStore.TryAdd(payload.Nonce, DateTimeOffset.UtcNow))
        {
            throw new CryptographicException("NONCE_REUSED");
        }

        // Cleanup expired nonces (5-min TTL)
        CleanupExpiredNonces();
    }

    /// <summary>
    /// Removes nonces older than 5 minutes from the store.
    /// Called on every nonce validation to prevent unbounded growth.
    /// </summary>
    private static void CleanupExpiredNonces()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-5);

        var expiredNonces = NonceStore
            .Where(kvp => kvp.Value < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var nonce in expiredNonces)
        {
            NonceStore.TryRemove(nonce, out _);
        }
    }
}
