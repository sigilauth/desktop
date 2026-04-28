using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sigil.Windows.Core.Crypto;
using Sigil.Windows.Core.Protocol;

/// <summary>
/// CLI harness for SIGIL-CONV-V1 wire protocol cross-implementation testing.
/// Supports domain-separated signing, session pictogram derivation, and envelope encrypt/decrypt.
/// </summary>
[RequiresUnreferencedCode("CryptoSign uses EnvelopeSigner which requires reflection")]
[RequiresDynamicCode("CryptoSign requires runtime code generation")]
sealed class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("SIGIL-CONV-V1 crypto test harness");

        rootCommand.AddCommand(BuildAuthCommand());
        rootCommand.AddCommand(BuildMpaCommand());
        rootCommand.AddCommand(BuildDecryptCommand());
        rootCommand.AddCommand(BuildPairHandshakeCommand());
        rootCommand.AddCommand(BuildEnvelopeEncryptCommand());
        rootCommand.AddCommand(BuildEnvelopeDecryptCommand());

        return await rootCommand.InvokeAsync(args);
    }

    static Command BuildAuthCommand()
    {
        var privOption = new Option<string>("--priv-hex", "Private key (hex-encoded 32 bytes)") { IsRequired = true };
        var challengeOption = new Option<string>("--challenge-hex", "Challenge bytes (hex-encoded 32 bytes)") { IsRequired = true };
        var actionContextOption = new Option<string>("--action-context-json", "Action context as canonical JSON") { IsRequired = true };

        var command = new Command("auth", "Sign authentication challenge with action_context binding")
        {
            privOption,
            challengeOption,
            actionContextOption
        };

        command.SetHandler((privHex, challengeHex, actionContextJson) =>
        {
            try
            {
                var privKeyBytes = Convert.FromHexString(privHex);
                if (privKeyBytes.Length != 32)
                {
                    Console.Error.WriteLine($"Invalid private key length: expected 32 bytes, got {privKeyBytes.Length}");
                    Environment.Exit(1);
                }

                var challengeBytes = Convert.FromHexString(challengeHex);
                if (challengeBytes.Length != 32)
                {
                    Console.Error.WriteLine($"Invalid challenge length: expected 32 bytes, got {challengeBytes.Length}");
                    Environment.Exit(1);
                }

                // Canonicalize action_context JSON (RFC 8785)
                var parsedJson = JsonSerializer.Deserialize<object>(actionContextJson);
                if (parsedJson == null)
                {
                    Console.Error.WriteLine("Failed to parse action context JSON");
                    Environment.Exit(1);
                }
                var canonicalJson = CanonicalJson.Serialize(parsedJson);

                // Hash the canonical action_context
                var actionHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson));

                // Build message: challenge_bytes || action_hash
                var message = new byte[64];
                Array.Copy(challengeBytes, 0, message, 0, 32);
                Array.Copy(actionHash, 0, message, 32, 32);

                SignAndOutput(privKeyBytes, DomainTag.Auth, message);
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"Invalid hex string: {ex.Message}");
                Environment.Exit(1);
            }
            catch (JsonException ex)
            {
                Console.Error.WriteLine($"Invalid JSON in --action-context-json: {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(2);
            }
        }, privOption, challengeOption, actionContextOption);

        return command;
    }

    static Command BuildMpaCommand()
    {
        var privOption = new Option<string>("--priv-hex", "Private key (hex-encoded 32 bytes)") { IsRequired = true };
        var messageOption = new Option<string>("--message-hex", "Message to sign (hex-encoded)") { IsRequired = true };

        var command = new Command("mpa", "Sign MPA action context")
        {
            privOption,
            messageOption
        };

        command.SetHandler((privHex, messageHex) =>
        {
            try
            {
                var privKeyBytes = Convert.FromHexString(privHex);
                if (privKeyBytes.Length != 32)
                {
                    Console.Error.WriteLine($"Invalid private key length: expected 32 bytes, got {privKeyBytes.Length}");
                    Environment.Exit(1);
                }

                var messageBytes = Convert.FromHexString(messageHex);

                SignAndOutput(privKeyBytes, DomainTag.Mpa, messageBytes);
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"Invalid hex string: {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(2);
            }
        }, privOption, messageOption);

        return command;
    }

    static Command BuildDecryptCommand()
    {
        var privOption = new Option<string>("--priv-hex", "Private key (hex-encoded 32 bytes)") { IsRequired = true };
        var messageOption = new Option<string>("--message-hex", "Message to sign (hex-encoded)") { IsRequired = true };

        var command = new Command("decrypt", "Sign decrypt envelope")
        {
            privOption,
            messageOption
        };

        command.SetHandler((privHex, messageHex) =>
        {
            try
            {
                var privKeyBytes = Convert.FromHexString(privHex);
                if (privKeyBytes.Length != 32)
                {
                    Console.Error.WriteLine($"Invalid private key length: expected 32 bytes, got {privKeyBytes.Length}");
                    Environment.Exit(1);
                }

                var messageBytes = Convert.FromHexString(messageHex);

                SignAndOutput(privKeyBytes, DomainTag.Decrypt, messageBytes);
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"Invalid hex string: {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(2);
            }
        }, privOption, messageOption);

        return command;
    }

    static Command BuildPairHandshakeCommand()
    {
        var serverPubOption = new Option<string>("--server-pub-hex", "Server public key (hex, 33 bytes compressed)") { IsRequired = true };
        var clientPubOption = new Option<string>("--client-pub-hex", "Client public key (hex, 33 bytes compressed)") { IsRequired = true };
        var serverNonceOption = new Option<string>("--server-nonce-hex", "Server nonce (hex, 32 bytes)") { IsRequired = true };

        var command = new Command("pair-handshake", "Derive session pictogram (Argon2id)")
        {
            serverPubOption,
            clientPubOption,
            serverNonceOption
        };

        command.SetHandler((serverPubHex, clientPubHex, serverNonceHex) =>
        {
            try
            {
                var serverPub = Convert.FromHexString(serverPubHex);
                if (serverPub.Length != 33)
                {
                    Console.Error.WriteLine($"Invalid server public key length: expected 33 bytes, got {serverPub.Length}");
                    Environment.Exit(1);
                }

                var clientPub = Convert.FromHexString(clientPubHex);
                if (clientPub.Length != 33)
                {
                    Console.Error.WriteLine($"Invalid client public key length: expected 33 bytes, got {clientPub.Length}");
                    Environment.Exit(1);
                }

                var serverNonce = Convert.FromHexString(serverNonceHex);
                if (serverNonce.Length != 32)
                {
                    Console.Error.WriteLine($"Invalid server nonce length: expected 32 bytes, got {serverNonce.Length}");
                    Environment.Exit(1);
                }

                var indices = SessionPictogram.DeriveIndices(serverPub, clientPub, serverNonce);

                // Convert indices to space-separated words
                var words = indices.Select(i => PictogramPool.GetEntry(i).Name);
                Console.Write(string.Join(" ", words));
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"Invalid hex string: {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(2);
            }
        }, serverPubOption, clientPubOption, serverNonceOption);

        return command;
    }

    static Command BuildEnvelopeEncryptCommand()
    {
        var senderPrivOption = new Option<string>("--sender-priv-hex", "Sender private key (hex, 32 bytes)") { IsRequired = true };
        var recipientPubOption = new Option<string>("--recipient-pub-hex", "Recipient public key (hex, 33 bytes compressed)") { IsRequired = true };
        var payloadOption = new Option<string>("--payload-json", "Payload as JSON string") { IsRequired = true };

        var command = new Command("envelope-encrypt", "Sign and encrypt request envelope")
        {
            senderPrivOption,
            recipientPubOption,
            payloadOption
        };

        command.SetHandler((senderPrivHex, recipientPubHex, payloadJson) =>
        {
            try
            {
                var senderPrivBytes = Convert.FromHexString(senderPrivHex);
                if (senderPrivBytes.Length != 32)
                {
                    Console.Error.WriteLine($"Invalid sender private key length: expected 32 bytes, got {senderPrivBytes.Length}");
                    Environment.Exit(1);
                }

                var recipientPub = Convert.FromHexString(recipientPubHex);
                if (recipientPub.Length != 33)
                {
                    Console.Error.WriteLine($"Invalid recipient public key length: expected 33 bytes, got {recipientPub.Length}");
                    Environment.Exit(1);
                }

                // Parse payload JSON
                var payload = JsonSerializer.Deserialize<RequestPayload>(payloadJson);
                if (payload == null)
                {
                    Console.Error.WriteLine("Failed to deserialize payload JSON");
                    Environment.Exit(1);
                }

                using var senderKey = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = senderPrivBytes
                });

                var senderParams = senderKey.ExportParameters(includePrivateParameters: true);
                var senderPubCompressed = ExportCompressedPublicKey(senderParams);

                var envelope = EnvelopeSigner.SignAndEncryptRequest(
                    payload,
                    senderKey,
                    senderPubCompressed,
                    recipientPub);

                Console.Write(envelope.Envelope);
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"Invalid hex string: {ex.Message}");
                Environment.Exit(1);
            }
            catch (JsonException ex)
            {
                Console.Error.WriteLine($"Invalid JSON in --payload-json: {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(2);
            }
        }, senderPrivOption, recipientPubOption, payloadOption);

        return command;
    }

    static Command BuildEnvelopeDecryptCommand()
    {
        var recipientPrivOption = new Option<string>("--recipient-priv-hex", "Recipient private key (hex, 32 bytes)") { IsRequired = true };
        var envelopeOption = new Option<string>("--envelope-base64", "Envelope (base64)") { IsRequired = true };

        var command = new Command("envelope-decrypt", "Decrypt and verify envelope")
        {
            recipientPrivOption,
            envelopeOption
        };

        command.SetHandler((recipientPrivHex, envelopeBase64) =>
        {
            try
            {
                var recipientPrivBytes = Convert.FromHexString(recipientPrivHex);
                if (recipientPrivBytes.Length != 32)
                {
                    Console.Error.WriteLine("ENVELOPE_INVALID");
                    Environment.Exit(2);
                }

                using var recipientKey = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = recipientPrivBytes
                });

                // Decode base64 outer envelope
                var outerCiphertext = Convert.FromBase64String(envelopeBase64);

                // Validate minimum envelope size: ephemeral_pub(33) + nonce(12) + tag(16) = 61 bytes
                if (outerCiphertext.Length < 61)
                {
                    Console.Error.WriteLine("ENVELOPE_INVALID");
                    Environment.Exit(2);
                }

                // Decrypt ECIES envelope (software key for CLI testing - not TPM)
#pragma warning disable CS0618 // CLI tool uses software keys (test harness), not TPM-backed keys
                var innerJson = Ecies.Decrypt(recipientKey, outerCiphertext);
#pragma warning restore CS0618
                var innerJsonString = Encoding.UTF8.GetString(innerJson);

                // Parse inner envelope structure
                var innerEnvelope = JsonSerializer.Deserialize<InnerEnvelope>(innerJsonString);
                if (innerEnvelope == null)
                {
                    Console.Error.WriteLine("MALFORMED_ENVELOPE");
                    Environment.Exit(2);
                }

                // Extract sender public key from envelope
                var senderPubCompressed = Convert.FromBase64String(innerEnvelope.ClientPublicKey);
                if (senderPubCompressed.Length != 33)
                {
                    Console.Error.WriteLine("MALFORMED_ENVELOPE");
                    Environment.Exit(2);
                }

                // Parse and validate payload required fields (ADV-07 protection)
                RequestPayload? payload;
                try
                {
                    payload = JsonSerializer.Deserialize<RequestPayload>(innerEnvelope.Payload);
                }
                catch (JsonException)
                {
                    Console.Error.WriteLine("ENVELOPE_INVALID");
                    Environment.Exit(2);
                    return;
                }

                if (payload == null ||
                    string.IsNullOrEmpty(payload.Action) ||
                    string.IsNullOrEmpty(payload.Nonce) ||
                    payload.Timestamp == 0 ||
                    string.IsNullOrEmpty(payload.Audience) ||
                    payload.Body == null)
                {
                    Console.Error.WriteLine("ENVELOPE_INVALID");
                    Environment.Exit(2);
                }

                // Re-canonicalize payload before signature verification (ADV-10 protection)
                string payloadCanonical = CanonicalizeJson(innerEnvelope.Payload);

                // Verify signature using embedded sender public key against canonical payload
                var signature = Convert.FromBase64String(innerEnvelope.Signature);
                var payloadBytes = Encoding.UTF8.GetBytes(payloadCanonical);

                if (!VerifySignature(senderPubCompressed, payloadBytes, signature, DomainTag.Conv))
                {
                    Console.Error.WriteLine("INVALID_SIGNATURE");
                    Environment.Exit(2);
                }

                // Output verified canonical payload
                Console.Write(payloadCanonical);
            }
            catch (FormatException)
            {
                Console.Error.WriteLine("ENVELOPE_INVALID");
                Environment.Exit(2);
            }
            catch (CryptographicException)
            {
                Console.Error.WriteLine("ENVELOPE_INVALID");
                Environment.Exit(2);
            }
            catch (JsonException)
            {
                Console.Error.WriteLine("MALFORMED_PAYLOAD");
                Environment.Exit(2);
            }
            catch (Exception)
            {
                Console.Error.WriteLine("ENVELOPE_INVALID");
                Environment.Exit(2);
            }
        }, recipientPrivOption, envelopeOption);

        return command;
    }

    static void SignAndOutput(byte[] privKeyBytes, byte[] domainTag, byte[] message)
    {
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privKeyBytes
        });

        var signature = EcdsaSign.Sign(ecdsa, message, domainTag);

        Console.Write(Convert.ToHexString(signature).ToLowerInvariant());
    }

    static bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature, byte[] domain)
    {
        if (signature.Length != 64)
        {
            return false;
        }

        // BIP-62 low-S check
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

        // Decompress public key to ECParameters (macOS-compatible)
        var ecParams = DecompressPublicKey(publicKey);
        using var ecdsa = ECDsa.Create(ecParams);

        Span<byte> tagged = stackalloc byte[domain.Length + message.Length];
        domain.CopyTo(tagged);
        message.CopyTo(tagged.Slice(domain.Length));

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(tagged, hash);

        return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    static int CompareBytes(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    static byte[] ExportSpkiFromCompressed(byte[] compressedPubKey)
    {
        if (compressedPubKey.Length != 33)
        {
            throw new ArgumentException("Compressed public key must be 33 bytes");
        }

        var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1");
        var domainParams = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
            curve.Curve, curve.G, curve.N, curve.H);

        var point = curve.Curve.DecodePoint(compressedPubKey);
        var pubKeyParams = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(point, domainParams);

        var subjectPublicKeyInfo = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKeyParams);
        return subjectPublicKeyInfo.GetDerEncoded();
    }

    static byte[] ExportCompressedPublicKey(ECParameters ecParams)
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

    static ECParameters DecompressPublicKey(byte[] compressedPubKey)
    {
        if (compressedPubKey.Length != 33)
        {
            throw new ArgumentException("Compressed public key must be 33 bytes");
        }

        var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1");
        var point = curve.Curve.DecodePoint(compressedPubKey);

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

        return new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = xPadded,
                Y = yPadded
            }
        };
    }

    /// <summary>
    /// Canonicalizes JSON per RFC 8785 (sorted keys, no whitespace, minimal encoding).
    /// </summary>
    private static string CanonicalizeJson(string json)
    {
        if (json == "{}")
        {
            return "{}";
        }

        // Parse and re-serialize with sorted properties and no whitespace
        using var doc = JsonDocument.Parse(json);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }))
        {
            WriteCanonical(writer, doc.RootElement);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                // Sort properties by name (lexicographic order)
                var properties = element.EnumerateObject()
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .ToList();
                foreach (var property in properties)
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonical(writer, item);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                // RFC 8785: Write numbers in canonical form
                if (element.TryGetInt64(out long longValue))
                {
                    writer.WriteNumberValue(longValue);
                }
                else if (element.TryGetDouble(out double doubleValue))
                {
                    writer.WriteNumberValue(doubleValue);
                }
                else
                {
                    // Fallback for numbers that don't fit int64 or double
                    writer.WriteRawValue(element.GetRawText());
                }
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;

            default:
                throw new ArgumentException($"Unsupported JSON value kind: {element.ValueKind}");
        }
    }
}
