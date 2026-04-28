using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Sigil.Windows.Core.Crypto;
using Sigil.Windows.Core.Protocol;
using Xunit;

namespace Sigil.Windows.Core.Tests;

[RequiresUnreferencedCode("EnvelopeSignerTests uses EnvelopeSigner")]
[RequiresDynamicCode("EnvelopeSignerTests requires runtime code generation")]
public sealed class EnvelopeSignerTests
{
    [Fact]
    public void SignAndEncryptRequest_ProducesValidEnvelope()
    {
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var clientParams = clientKey.ExportParameters(includePrivateParameters: true);
        var serverParams = serverKey.ExportParameters(includePrivateParameters: true);

        var clientPubCompressed = ExportCompressedPublicKey(clientParams);
        var serverPubCompressed = ExportCompressedPublicKey(serverParams);

        var payload = new RequestPayload(
            Action: "test.action",
            Body: new { test = "value" },
            Timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Nonce: Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            Audience: Convert.ToHexString(SHA256.HashData(serverPubCompressed)).ToLowerInvariant());

        var envelope = EnvelopeSigner.SignAndEncryptRequest(
            payload,
            clientKey,
            clientPubCompressed,
            serverPubCompressed);

        Assert.NotNull(envelope.Envelope);
        Assert.NotEmpty(envelope.Envelope);

        var ciphertext = Convert.FromBase64String(envelope.Envelope);
        Assert.True(ciphertext.Length > 61);
    }

    [Fact]
    public void DecryptAndVerifyResponse_ValidatesSignature()
    {
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var clientParams = clientKey.ExportParameters(includePrivateParameters: true);
        var serverParams = serverKey.ExportParameters(includePrivateParameters: true);

        var clientPubCompressed = ExportCompressedPublicKey(clientParams);
        var serverPubCompressed = ExportCompressedPublicKey(serverParams);

        var responsePayload = new ResponsePayload(
            Status: "ok",
            Body: new { result = "success" },
            Timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Nonce: Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant());

        var canonicalPayload = CanonicalJson.Serialize(responsePayload);
        var signature = EcdsaSign.Sign(serverKey, System.Text.Encoding.UTF8.GetBytes(canonicalPayload), DomainTag.Conv);

        var innerEnvelope = new InnerEnvelope(
            ClientPublicKey: Convert.ToBase64String(serverPubCompressed),
            Payload: canonicalPayload,
            Signature: Convert.ToBase64String(signature));

        var innerJson = CanonicalJson.Serialize(innerEnvelope);
        var outerCiphertext = Ecies.Encrypt(clientPubCompressed, System.Text.Encoding.UTF8.GetBytes(innerJson));

        var envelope = new OuterEnvelope(Envelope: Convert.ToBase64String(outerCiphertext));

        var decrypted = EnvelopeSigner.DecryptAndVerifyResponse(envelope, clientKey, serverPubCompressed);

        Assert.Equal("ok", decrypted.Status);
    }

    [Fact]
    public void DecryptAndVerifyResponse_InvalidSignature_Throws()
    {
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var clientParams = clientKey.ExportParameters(includePrivateParameters: true);
        var serverParams = serverKey.ExportParameters(includePrivateParameters: true);

        var clientPubCompressed = ExportCompressedPublicKey(clientParams);
        var serverPubCompressed = ExportCompressedPublicKey(serverParams);

        var responsePayload = new ResponsePayload(
            Status: "ok",
            Body: new { result = "success" },
            Timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Nonce: Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant());

        var canonicalPayload = CanonicalJson.Serialize(responsePayload);
        var attackerSignature = EcdsaSign.Sign(attackerKey, System.Text.Encoding.UTF8.GetBytes(canonicalPayload), DomainTag.Conv);

        var innerEnvelope = new InnerEnvelope(
            ClientPublicKey: Convert.ToBase64String(serverPubCompressed),
            Payload: canonicalPayload,
            Signature: Convert.ToBase64String(attackerSignature));

        var innerJson = CanonicalJson.Serialize(innerEnvelope);
        var outerCiphertext = Ecies.Encrypt(clientPubCompressed, System.Text.Encoding.UTF8.GetBytes(innerJson));

        var envelope = new OuterEnvelope(Envelope: Convert.ToBase64String(outerCiphertext));

        Assert.Throws<CryptographicException>(() =>
            EnvelopeSigner.DecryptAndVerifyResponse(envelope, clientKey, serverPubCompressed));
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
