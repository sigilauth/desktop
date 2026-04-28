using System.Security.Cryptography;

namespace Sigil.Windows.Core.Crypto;

/// <summary>
/// ECDSA P-256 signing with domain separation per api/domain-separation.md.
/// </summary>
public static class EcdsaSign
{
    /// <summary>
    /// Signs a message with domain separation.
    /// Returns 64-byte R||S signature (IEEE P1363 format), low-S normalized per BIP-62.
    /// </summary>
    /// <param name="key">ECDSA P-256 private key</param>
    /// <param name="message">Message bytes to sign</param>
    /// <param name="domain">Domain tag (e.g. DomainTag.Auth)</param>
    /// <returns>64-byte signature (R||S)</returns>
    public static byte[] Sign(ECDsa key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> domain)
    {
        // Concatenate domain tag + message
        Span<byte> tagged = stackalloc byte[domain.Length + message.Length];
        domain.CopyTo(tagged);
        message.CopyTo(tagged.Slice(domain.Length));

        // Hash the tagged input
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(tagged, hash);

        // Sign the hash with IEEE P1363 format (R||S 64 bytes)
        Span<byte> signature = stackalloc byte[64];
        if (!key.TrySignHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out var bytesWritten)
            || bytesWritten != 64)
        {
            throw new CryptographicException("ECDSA signing failed or produced wrong length signature");
        }

        // Normalize to low-S per BIP-62
        NormalizeLowS(signature);

        return signature.ToArray();
    }

    /// <summary>
    /// Normalizes ECDSA signature to low-S form per BIP-62.
    /// If S > N/2, replace S with N - S.
    /// Modifies signature in-place.
    /// </summary>
    private static void NormalizeLowS(Span<byte> signature)
    {
        // P-256 curve order N (secp256r1)
        ReadOnlySpan<byte> N = stackalloc byte[32]
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
        };

        // N/2 (for comparison)
        ReadOnlySpan<byte> halfN = stackalloc byte[32]
        {
            0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
            0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
        };

        // Extract S (second 32 bytes)
        Span<byte> s = signature.Slice(32, 32);

        // Compare S with N/2 (big-endian comparison)
        if (CompareBytes(s, halfN) > 0)
        {
            // S > N/2, so replace with N - S
            SubtractFromN(s, N);
        }
    }

    /// <summary>
    /// Compares two byte spans as big-endian unsigned integers.
    /// Returns: -1 if a &lt; b, 0 if a == b, 1 if a &gt; b
    /// </summary>
    private static int CompareBytes(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    /// <summary>
    /// Subtracts S from N in-place: S := N - S
    /// Big-endian subtraction with borrow.
    /// </summary>
    private static void SubtractFromN(Span<byte> s, ReadOnlySpan<byte> n)
    {
        int borrow = 0;
        for (int i = 31; i >= 0; i--)
        {
            int diff = n[i] - s[i] - borrow;
            if (diff < 0)
            {
                diff += 256;
                borrow = 1;
            }
            else
            {
                borrow = 0;
            }
            s[i] = (byte)diff;
        }
    }
}
