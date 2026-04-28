using System.Security.Cryptography;
using Sigil.Windows.Core.Crypto;
using Xunit;

namespace Sigil.Windows.Core.Tests;

public sealed class EciesTests
{
    [Fact]
    public void Encrypt_Decrypt_RoundTrip()
    {
        using var recipientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipientParams = recipientKey.ExportParameters(includePrivateParameters: true);
        var recipientPubCompressed = ExportCompressedPublicKey(recipientParams);

        var plaintext = "test message"u8.ToArray();

        var ciphertext = Ecies.Encrypt(recipientPubCompressed, plaintext);

        var decrypted = Ecies.Decrypt(recipientKey, ciphertext);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesCorrectWireFormat()
    {
        using var recipientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipientParams = recipientKey.ExportParameters(includePrivateParameters: true);
        var recipientPubCompressed = ExportCompressedPublicKey(recipientParams);

        var plaintext = "short"u8.ToArray();

        var ciphertext = Ecies.Encrypt(recipientPubCompressed, plaintext);

        Assert.True(ciphertext.Length >= 61);
        Assert.Equal(33, ciphertext[..33].Length);
        Assert.Equal(12, ciphertext[33..45].Length);
        Assert.Equal(16, ciphertext[^16..].Length);
    }

    [Fact]
    public void Encrypt_DifferentEphemeralKeyEachTime()
    {
        using var recipientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipientParams = recipientKey.ExportParameters(includePrivateParameters: true);
        var recipientPubCompressed = ExportCompressedPublicKey(recipientParams);

        var plaintext = "test"u8.ToArray();

        var ciphertext1 = Ecies.Encrypt(recipientPubCompressed, plaintext);
        var ciphertext2 = Ecies.Encrypt(recipientPubCompressed, plaintext);

        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Decrypt_InvalidTag_Throws()
    {
        using var recipientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipientParams = recipientKey.ExportParameters(includePrivateParameters: true);
        var recipientPubCompressed = ExportCompressedPublicKey(recipientParams);

        var plaintext = "test"u8.ToArray();
        var ciphertext = Ecies.Encrypt(recipientPubCompressed, plaintext);

        ciphertext[^1] ^= 0xFF;

        Assert.Throws<CryptographicException>(() => Ecies.Decrypt(recipientKey, ciphertext));
    }

    private static byte[] ExportCompressedPublicKey(ECParameters ecParams)
    {
        if (ecParams.Q.X == null || ecParams.Q.Y == null)
        {
            throw new ArgumentException("ECParameters missing public key coordinates");
        }

        var compressed = new byte[33];
        compressed[0] = (byte)((ecParams.Q.Y[^1] & 1) == 0 ? 0x02 : 0x03);
        Array.Copy(ecParams.Q.X, 0, compressed, 1, 32);

        return compressed;
    }
}
