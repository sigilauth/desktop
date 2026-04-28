using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Sigil.Windows.Core.Crypto;

/// <summary>
/// ECIES encryption/decryption for SIGIL-CONV-V1 wire protocol.
/// Per api/wire-protocol.md section 2.3:
/// - P-256 ECDH ephemeral key exchange
/// - HKDF-SHA256 key derivation
/// - AES-256-GCM authenticated encryption
/// </summary>
public static class Ecies
{
    private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("secp256r1");
    private static readonly ECDomainParameters DomainParams = new(Curve.Curve, Curve.G, Curve.N, Curve.H);

    /// <summary>
    /// Encrypts plaintext to recipient's static public key using ECIES.
    /// Wire format: ephemeral_public (33) || nonce (12) || ciphertext || tag (16)
    /// </summary>
    /// <param name="recipientPublicKey">Recipient's static P-256 public key (33 bytes compressed)</param>
    /// <param name="plaintext">Data to encrypt</param>
    /// <returns>ECIES envelope</returns>
    public static byte[] Encrypt(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> plaintext)
    {
        if (recipientPublicKey.Length != 33)
        {
            throw new ArgumentException("Recipient public key must be 33 bytes (compressed P-256)", nameof(recipientPublicKey));
        }

        var recipientPoint = DecodePublicKey(recipientPublicKey);
        var recipientPubKey = new ECPublicKeyParameters(recipientPoint, DomainParams);

        var ephemeralKeyPair = GenerateEphemeralKeypair();
        var ephemeralPrivate = (ECPrivateKeyParameters)ephemeralKeyPair.Private;
        var ephemeralPublic = (ECPublicKeyParameters)ephemeralKeyPair.Public;

        var sharedSecret = ComputeSharedSecret(ephemeralPrivate, recipientPubKey);

        var recipientFingerprint = SHA256.HashData(recipientPublicKey);
        var aesKey = DeriveAesKey(sharedSecret, recipientFingerprint);

        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        var ephemeralPublicCompressed = EncodePublicKey(ephemeralPublic.Q);

        using var aes = new AesGcm(aesKey, 16);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        aes.Encrypt(nonce, plaintext, ciphertext, tag, ephemeralPublicCompressed);

        var envelope = new byte[33 + 12 + ciphertext.Length + 16];
        ephemeralPublicCompressed.CopyTo(envelope, 0);
        nonce.CopyTo(envelope, 33);
        ciphertext.CopyTo(envelope, 45);
        tag.CopyTo(envelope, 45 + ciphertext.Length);

        return envelope;
    }

    /// <summary>
    /// Decrypts ECIES envelope using recipient's static private key (TPM-safe).
    /// </summary>
    /// <param name="recipientPrivateKey">Recipient's ECDH key (CNG/TPM-backed)</param>
    /// <param name="envelope">ECIES envelope from Encrypt</param>
    /// <returns>Decrypted plaintext</returns>
    /// <remarks>
    /// This overload performs ECDH inside CNG/TPM via DeriveRawSecretAgreement().
    /// Returns raw shared X coordinate (no internal hashing) for cross-impl compatibility.
    /// Private key never leaves hardware. Use this for production with TPM-backed keys.
    /// </remarks>
    public static byte[] Decrypt(ECDiffieHellmanCng recipientPrivateKey, ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < 61)
        {
            throw new ArgumentException("Envelope too short (minimum 61 bytes)", nameof(envelope));
        }

        var ephemeralPublicCompressed = envelope.Slice(0, 33);
        var nonce = envelope.Slice(33, 12);

        // CRITICAL FIX: Convert parent slice to array FIRST to avoid offset accumulation bug
        // Slicing a ReadOnlySpan that is already a slice causes incorrect boundaries
        var ctAndTagArray = envelope.Slice(45).ToArray();

        if (ctAndTagArray.Length < 16)
        {
            throw new ArgumentException("Envelope missing authentication tag", nameof(envelope));
        }

        var ciphertext = ctAndTagArray[0..^16];
        var tag = ctAndTagArray[^16..];

        // Convert ephemeral compressed pubkey to ECDiffieHellmanPublicKey for CNG ECDH
        using var ephemeralPub = ImportEphemeralPublicKey(ephemeralPublicCompressed);

        // ECDH inside CNG/TPM — private key never exported (SIG-2026-RAVEN-P8 fix)
        // Use DeriveRawSecretAgreement() to get raw shared X (SIG-2026-RAVEN-P17 fix)
        // DeriveKeyMaterial() defaults to SHA256(shared_x) which breaks cross-impl compatibility
        var sharedSecret = recipientPrivateKey.DeriveRawSecretAgreement(ephemeralPub);

        // Export recipient's public key for fingerprint derivation
        var recipientPublicKey = ExportRecipientCompressed(recipientPrivateKey);
        var recipientFingerprint = SHA256.HashData(recipientPublicKey);
        var aesKey = DeriveAesKey(sharedSecret, recipientFingerprint);

        using var aes = new AesGcm(aesKey, 16);
        var plaintext = new byte[ciphertext.Length];

        // CRITICAL FIX: Convert all ReadOnlySpan parameters to arrays for AesGcm.Decrypt
        aes.Decrypt(nonce.ToArray(), ciphertext, tag, plaintext, ephemeralPublicCompressed.ToArray());

        return plaintext;
    }

    /// <summary>
    /// Decrypts ECIES envelope using recipient's static private key (SOFTWARE ONLY - NOT TPM-SAFE).
    /// </summary>
    /// <param name="recipientPrivateKey">Recipient's static P-256 private key (ECDsa instance)</param>
    /// <param name="envelope">ECIES envelope from Encrypt</param>
    /// <returns>Decrypted plaintext</returns>
    /// <remarks>
    /// WARNING (SIG-2026-RAVEN-P8): This overload calls ExportParameters(true), which exports
    /// the private key D scalar into managed memory. If the ECDsa instance is TPM-backed,
    /// this violates "private key never leaves hardware". Use the ECDiffieHellmanCng overload
    /// for production with TPM keys. This overload is provided for software keys (testing, CLI tools).
    /// </remarks>
    [Obsolete("Use ECDiffieHellmanCng overload for TPM-backed keys to avoid private key export (SIG-2026-RAVEN-P8)")]
    public static byte[] Decrypt(ECDsa recipientPrivateKey, ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < 61)
        {
            throw new ArgumentException("Envelope too short (minimum 61 bytes)", nameof(envelope));
        }

        var ephemeralPublicCompressed = envelope.Slice(0, 33);
        var nonce = envelope.Slice(33, 12);

        // CRITICAL FIX: Convert parent slice to array FIRST to avoid offset accumulation bug
        // Slicing a ReadOnlySpan that is already a slice causes incorrect boundaries
        var ctAndTagArray = envelope.Slice(45).ToArray();

        if (ctAndTagArray.Length < 16)
        {
            throw new ArgumentException("Envelope missing authentication tag", nameof(envelope));
        }

        var ciphertext = ctAndTagArray[0..^16];
        var tag = ctAndTagArray[^16..];

        var ephemeralPoint = DecodePublicKey(ephemeralPublicCompressed);
        var ephemeralPubKey = new ECPublicKeyParameters(ephemeralPoint, DomainParams);

        var recipientParams = recipientPrivateKey.ExportParameters(true);
        var d = new BigInteger(1, recipientParams.D);
        var recipientPrivKey = new ECPrivateKeyParameters(d, DomainParams);

        var sharedSecret = ComputeSharedSecret(recipientPrivKey, ephemeralPubKey);
        var recipientPublicKey = EncodePublicKey(recipientParams);
        var recipientFingerprint = SHA256.HashData(recipientPublicKey);
        var aesKey = DeriveAesKey(sharedSecret, recipientFingerprint);

        using var aes = new AesGcm(aesKey, 16);
        var plaintext = new byte[ciphertext.Length];

        var nonceArray = nonce.ToArray();
        var aadArray = ephemeralPublicCompressed.ToArray();

        aes.Decrypt(nonceArray, ciphertext, tag, plaintext, aadArray);

        return plaintext;
    }

    private static AsymmetricCipherKeyPair GenerateEphemeralKeypair()
    {
        var generator = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(DomainParams, new Org.BouncyCastle.Security.SecureRandom()));
        return generator.GenerateKeyPair();
    }

    private static byte[] ComputeSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
    {
        var sharedPoint = publicKey.Q.Multiply(privateKey.D).Normalize();
        var sharedX = sharedPoint.XCoord.ToBigInteger().ToByteArrayUnsigned();

        var sharedSecret = new byte[32];
        if (sharedX.Length <= 32)
        {
            sharedX.CopyTo(sharedSecret, 32 - sharedX.Length);
        }
        else
        {
            Array.Copy(sharedX, sharedX.Length - 32, sharedSecret, 0, 32);
        }

        return sharedSecret;
    }

    private static byte[] DeriveAesKey(byte[] sharedSecret, byte[] salt)
    {
        const string info = "SIGIL-CONV-V1-AES256";
        var infoBytes = System.Text.Encoding.UTF8.GetBytes(info);

        var key = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, key, salt, infoBytes);
        return key;
    }

    private static Org.BouncyCastle.Math.EC.ECPoint DecodePublicKey(ReadOnlySpan<byte> compressed)
    {
        return Curve.Curve.DecodePoint(compressed.ToArray());
    }

    private static byte[] EncodePublicKey(Org.BouncyCastle.Math.EC.ECPoint point)
    {
        return point.GetEncoded(compressed: true);
    }

    private static byte[] EncodePublicKey(ECParameters ecParams)
    {
        if (ecParams.Q.X == null || ecParams.Q.Y == null)
        {
            throw new ArgumentException("ECParameters missing public key coordinates");
        }

        var x = new BigInteger(1, ecParams.Q.X);
        var y = new BigInteger(1, ecParams.Q.Y);
        var point = Curve.Curve.CreatePoint(x, y);

        return point.GetEncoded(compressed: true);
    }

    /// <summary>
    /// Imports ephemeral compressed public key as ECDiffieHellmanPublicKey for CNG ECDH.
    /// </summary>
    /// <param name="compressed">Compressed P-256 public key (33 bytes)</param>
    /// <returns>ECDiffieHellmanPublicKey instance</returns>
    private static ECDiffieHellmanPublicKey ImportEphemeralPublicKey(ReadOnlySpan<byte> compressed)
    {
        if (compressed.Length != 33)
        {
            throw new ArgumentException("Compressed public key must be 33 bytes");
        }

        // Convert compressed format to uncompressed (65 bytes: 0x04 || X || Y)
        var point = DecodePublicKey(compressed);
        var x = point.XCoord.ToBigInteger().ToByteArrayUnsigned();
        var y = point.YCoord.ToBigInteger().ToByteArrayUnsigned();

        // Pad to 32 bytes if needed
        var xPadded = new byte[32];
        var yPadded = new byte[32];
        if (x.Length <= 32)
            x.CopyTo(xPadded, 32 - x.Length);
        else
            Array.Copy(x, x.Length - 32, xPadded, 0, 32);

        if (y.Length <= 32)
            y.CopyTo(yPadded, 32 - y.Length);
        else
            Array.Copy(y, y.Length - 32, yPadded, 0, 32);

        // Build ECPoint (X, Y)
        var ecParams = new ECParameters
        {
            Curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
            Q = new System.Security.Cryptography.ECPoint
            {
                X = xPadded,
                Y = yPadded
            }
        };

        // Import as ECDiffieHellmanPublicKey
        using var ecdh = ECDiffieHellman.Create(ecParams);
        return ecdh.PublicKey;
    }

    /// <summary>
    /// Exports recipient's compressed public key from ECDiffieHellmanCng instance.
    /// </summary>
    /// <param name="ecdh">ECDiffieHellmanCng instance</param>
    /// <returns>Compressed P-256 public key (33 bytes)</returns>
    private static byte[] ExportRecipientCompressed(ECDiffieHellmanCng ecdh)
    {
        var ecParams = ecdh.ExportParameters(includePrivateParameters: false);
        return EncodePublicKey(ecParams);
    }
}
