using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sigil.Windows.Core.Crypto;
using Xunit;

namespace Sigil.Windows.Core.Tests;

/// <summary>
/// Domain separation signature tests against cross-platform test vectors.
/// Verifies byte-for-byte compatibility with Terra (Linux) and Nova (mobile) implementations.
/// </summary>
public sealed class DomainSeparationTests
{
    private const string FixturesPath = "Fixtures/domain-separation";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    [Fact]
    public void AuthV1_AllVectors_ProduceExpectedSignatures()
    {
        var testData = LoadTestVectors($"{FixturesPath}/auth-v1.json");

        foreach (var vector in testData.Vectors)
        {
            // Arrange
            using var key = LoadPrivateKey(vector.PrivateKeyHex);
            var message = Convert.FromHexString(vector.MessageHex);
            var domainTag = DomainTag.Auth;

            // Act
            var signature = EcdsaSign.Sign(key, message, domainTag);

            // Assert
            var expectedSignature = Convert.FromHexString(vector.ExpectedSignatureHex);
            Assert.Equal(expectedSignature, signature);
        }
    }

    [Fact]
    public void MpaV1_AllVectors_ProduceExpectedSignatures()
    {
        var testData = LoadTestVectors($"{FixturesPath}/mpa-v1.json");

        foreach (var vector in testData.Vectors)
        {
            // Arrange
            using var key = LoadPrivateKey(vector.PrivateKeyHex);
            var message = Convert.FromHexString(vector.MessageHex);
            var domainTag = DomainTag.Mpa;

            // Act
            var signature = EcdsaSign.Sign(key, message, domainTag);

            // Assert
            var expectedSignature = Convert.FromHexString(vector.ExpectedSignatureHex);
            Assert.Equal(expectedSignature, signature);
        }
    }

    [Fact]
    public void DecryptV1_AllVectors_ProduceExpectedSignatures()
    {
        var testData = LoadTestVectors($"{FixturesPath}/decrypt-v1.json");

        foreach (var vector in testData.Vectors)
        {
            // Arrange
            using var key = LoadPrivateKey(vector.PrivateKeyHex);
            var message = Convert.FromHexString(vector.MessageHex);
            var domainTag = DomainTag.Decrypt;

            // Act
            var signature = EcdsaSign.Sign(key, message, domainTag);

            // Assert
            var expectedSignature = Convert.FromHexString(vector.ExpectedSignatureHex);
            Assert.Equal(expectedSignature, signature);
        }
    }

    [Fact]
    public void CrossDomain_AuthSignature_DoesNotVerifyUnderMpaDomain()
    {
        // Arrange
        var testData = LoadTestVectors($"{FixturesPath}/auth-v1.json");
        var vector = testData.Vectors[0];

        using var key = LoadPrivateKey(vector.PrivateKeyHex);
        var message = Convert.FromHexString(vector.MessageHex);

        // Sign with Auth domain
        var authSignature = EcdsaSign.Sign(key, message, DomainTag.Auth);

        // Create hash with MPA domain for verification
        Span<byte> mpaTaggedInput = stackalloc byte[DomainTag.Mpa.Length + message.Length];
        DomainTag.Mpa.CopyTo(mpaTaggedInput);
        message.CopyTo(mpaTaggedInput.Slice(DomainTag.Mpa.Length));
        Span<byte> mpaHash = stackalloc byte[32];
        SHA256.HashData(mpaTaggedInput, mpaHash);

        // Act - try to verify Auth signature against MPA hash
        var publicKey = key.ExportParameters(false);
        using var verifyKey = ECDsa.Create(publicKey);
        var verified = verifyKey.VerifyHash(mpaHash, authSignature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        // Assert - verification must fail
        Assert.False(verified, "Signature created with Auth domain tag must not verify with MPA domain tag");
    }

    [Fact]
    public void CrossDomain_MpaSignature_DoesNotVerifyUnderAuthDomain()
    {
        // Arrange
        var testData = LoadTestVectors($"{FixturesPath}/mpa-v1.json");
        var vector = testData.Vectors[0];

        using var key = LoadPrivateKey(vector.PrivateKeyHex);
        var message = Convert.FromHexString(vector.MessageHex);

        // Sign with MPA domain
        var mpaSignature = EcdsaSign.Sign(key, message, DomainTag.Mpa);

        // Create hash with Auth domain for verification
        Span<byte> authTaggedInput = stackalloc byte[DomainTag.Auth.Length + message.Length];
        DomainTag.Auth.CopyTo(authTaggedInput);
        message.CopyTo(authTaggedInput.Slice(DomainTag.Auth.Length));
        Span<byte> authHash = stackalloc byte[32];
        SHA256.HashData(authTaggedInput, authHash);

        // Act - try to verify MPA signature against Auth hash
        var publicKey = key.ExportParameters(false);
        using var verifyKey = ECDsa.Create(publicKey);
        var verified = verifyKey.VerifyHash(authHash, mpaSignature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        // Assert - verification must fail
        Assert.False(verified, "Signature created with MPA domain tag must not verify with Auth domain tag");
    }

    [Fact]
    public void Signature_IsAlwaysLowS()
    {
        // Arrange - create key and sign multiple messages to test normalization
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var messages = new[]
        {
            "test message 1"u8.ToArray(),
            "test message 2"u8.ToArray(),
            "test message 3"u8.ToArray()
        };

        // P-256 curve order N / 2
        ReadOnlySpan<byte> halfN = stackalloc byte[32]
        {
            0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
            0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
        };

        foreach (var message in messages)
        {
            // Act
            var signature = EcdsaSign.Sign(key, message, DomainTag.Auth);

            // Assert - S value (second 32 bytes) must be <= N/2
            var s = signature.AsSpan(32, 32);
            var isLowS = CompareBytes(s, halfN) <= 0;
            Assert.True(isLowS, "Signature S value must be normalized to low-S per BIP-62");
        }
    }

    private static ECDsa LoadPrivateKey(string privateKeyHex)
    {
        var d = Convert.FromHexString(privateKeyHex);
        var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d
        });
        return key;
    }

    private static TestVectorFile LoadTestVectors(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<TestVectorFile>(json, JsonOptions)
            ?? throw new InvalidOperationException($"Failed to deserialize test vectors from {path}");
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

    private sealed class TestVectorFile
    {
        public required List<TestVector> Vectors { get; init; }
    }

    private sealed class TestVector
    {
        public required string Name { get; init; }
        public required string PrivateKeyHex { get; init; }
        public required string MessageHex { get; init; }
        public required string ExpectedSignatureHex { get; init; }
    }
}
