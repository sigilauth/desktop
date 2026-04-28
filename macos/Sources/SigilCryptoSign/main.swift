import Foundation
import CryptoKit
import SigilAuth

enum CryptoSignError: Error {
    case invalidArguments
    case invalidHexString
    case keyGenerationFailed
    case signingFailed
    case verificationFailed
    case envelopeFailed
}

func printUsage() {
    print("""
    SigilCryptoSign - SIGIL-CONV-V1 CLI Tool

    USAGE:
        crypto-sign sign <message_hex> <private_key_hex>
            Sign message with SIGIL-CONV-V1 domain tag

        crypto-sign verify <message_hex> <signature_hex> <public_key_hex>
            Verify SIGIL-CONV-V1 signature

        crypto-sign keygen
            Generate new P-256 keypair

        crypto-sign envelope <action> <body_json> <client_key_hex> <server_pubkey_hex>
            Create SIGIL-CONV-V1 envelope

        crypto-sign envelope-decrypt --recipient-priv-hex <hex> --envelope-base64 <b64>
            Decrypt SIGIL-CONV-V1 envelope

    EXAMPLES:
        crypto-sign keygen
        crypto-sign sign deadbeef <private_key>
        crypto-sign envelope challenge.create '{"user":"alice"}' <key> <server_pub>
        crypto-sign envelope-decrypt --recipient-priv-hex abc123... --envelope-base64 def456...
    """)
}

func hexToData(_ hex: String) throws -> Data {
    var data = Data()
    var hex = hex
    if hex.hasPrefix("0x") {
        hex = String(hex.dropFirst(2))
    }

    guard hex.count % 2 == 0 else {
        throw CryptoSignError.invalidHexString
    }

    for i in stride(from: 0, to: hex.count, by: 2) {
        let start = hex.index(hex.startIndex, offsetBy: i)
        let end = hex.index(start, offsetBy: 2)
        let byteString = String(hex[start..<end])
        guard let byte = UInt8(byteString, radix: 16) else {
            throw CryptoSignError.invalidHexString
        }
        data.append(byte)
    }

    return data
}

func dataToHex(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

func generateKeypair() {
    let privateKey = P256.Signing.PrivateKey()
    let publicKey = privateKey.publicKey

    let privateKeyHex = dataToHex(privateKey.rawRepresentation)
    let publicKeyCompressedHex = dataToHex(publicKey.compressedRepresentation)

    print("Private Key (hex):")
    print(privateKeyHex)
    print("\nPublic Key (compressed, hex):")
    print(publicKeyCompressedHex)
}

func signMessage(_ messageHex: String, _ privateKeyHex: String) throws {
    let message = try hexToData(messageHex)
    let privateKeyData = try hexToData(privateKeyHex)

    let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)

    var tagged = Data(DomainTag.conv)
    tagged.append(message)
    let hash = Data(SHA256.hash(data: tagged))

    let signature = try privateKey.signature(for: hash)

    print("Signature (DER, hex):")
    print(dataToHex(signature.derRepresentation))
}

func verifySignature(_ messageHex: String, _ signatureHex: String, _ publicKeyHex: String) throws {
    let message = try hexToData(messageHex)
    let signatureData = try hexToData(signatureHex)
    let publicKeyData = try hexToData(publicKeyHex)

    let publicKey = try P256.Signing.PublicKey(compressedRepresentation: publicKeyData)

    var tagged = Data(DomainTag.conv)
    tagged.append(message)
    let hash = Data(SHA256.hash(data: tagged))

    let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)

    let isValid = publicKey.isValidSignature(signature, for: hash)

    print("Signature valid: \(isValid)")
    if !isValid {
        throw CryptoSignError.verificationFailed
    }
}

func createEnvelope(_ action: String, _ bodyJSON: String, _ clientKeyHex: String, _ serverPubHex: String) throws {
    let clientPrivateKeyData = try hexToData(clientKeyHex)
    let serverPublicKey = try hexToData(serverPubHex)

    let clientPrivateKey = try P256.Signing.PrivateKey(rawRepresentation: clientPrivateKeyData)
    let clientPublicKey = clientPrivateKey.publicKey.compressedRepresentation

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits as String: 256
    ]

    var error: Unmanaged<CFError>?
    let clientSecKey = SecKeyCreateWithData(
        clientPrivateKeyData as CFData,
        attributes as CFDictionary,
        &error
    )

    guard let secKey = clientSecKey else {
        throw CryptoSignError.keyGenerationFailed
    }

    guard let bodyData = bodyJSON.data(using: .utf8),
          let bodyDict = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any] else {
        throw CryptoSignError.invalidArguments
    }

    let timestamp = Int64(Date().timeIntervalSince1970)
    let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "")
    let audience = dataToHex(Data(SHA256.hash(data: serverPublicKey)))

    let payload = EnvelopePayload(
        action: action,
        body: bodyDict,
        timestamp: timestamp,
        nonce: nonce,
        audience: audience
    )

    let envelopeService = DefaultEnvelopeService()

    let envelopeData = try envelopeService.createRequest(
        payload: payload,
        clientPrivateKey: secKey,
        clientPublicKey: clientPublicKey,
        serverPublicKey: serverPublicKey
    )

    print("Envelope (JSON):")
    if let jsonString = String(data: envelopeData, encoding: .utf8) {
        print(jsonString)
    }
}

func decryptEnvelope(privHex: String, envelopeBase64: String) {
    do {
        let recipientPrivateKeyData = try hexToData(privHex)
        guard recipientPrivateKeyData.count == 32 else {
            fputs("INVALID_KEY_LENGTH\n", stderr)
            exit(1)
        }

        guard let envelopeCiphertext = Data(base64Encoded: envelopeBase64) else {
            fputs("INVALID_ENVELOPE_ENCODING\n", stderr)
            exit(1)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256
        ]

        var error: Unmanaged<CFError>?
        guard let recipientSecKey = SecKeyCreateWithData(
            recipientPrivateKeyData as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            fputs("INVALID_PRIVATE_KEY\n", stderr)
            exit(1)
        }

        let eciesService = DefaultECIESService()
        let innerJSON: Data
        do {
            innerJSON = try eciesService.decrypt(ciphertext: envelopeCiphertext, recipientPrivateKey: recipientSecKey)
        } catch {
            fputs("ENVELOPE_INVALID\n", stderr)
            exit(2)
        }

        guard let innerDict = try? JSONSerialization.jsonObject(with: innerJSON) as? [String: Any],
              let clientPubB64 = innerDict["client_public_key"] as? String,
              let payloadStr = innerDict["payload"] as? String,
              let signatureB64 = innerDict["signature"] as? String else {
            fputs("MALFORMED_ENVELOPE\n", stderr)
            exit(2)
        }

        guard let clientPublicKey = Data(base64Encoded: clientPubB64),
              let payloadData = payloadStr.data(using: .utf8),
              let signature = Data(base64Encoded: signatureB64) else {
            fputs("MALFORMED_ENVELOPE\n", stderr)
            exit(2)
        }

        guard signature.count == 64 else {
            fputs("INVALID_SIGNATURE\n", stderr)
            exit(2)
        }

        var tagged = Data(DomainTag.conv)
        tagged.append(payloadData)
        let hash = SHA256.hash(data: tagged)

        guard let clientP256Key = try? P256.Signing.PublicKey(compressedRepresentation: clientPublicKey) else {
            fputs("INVALID_SIGNATURE\n", stderr)
            exit(2)
        }

        guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
            fputs("INVALID_SIGNATURE\n", stderr)
            exit(2)
        }

        let isValid = clientP256Key.isValidSignature(ecdsaSignature, for: hash)
        guard isValid else {
            fputs("INVALID_SIGNATURE\n", stderr)
            exit(2)
        }

        guard let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            fputs("MALFORMED_PAYLOAD\n", stderr)
            exit(2)
        }

        let canonicalOutput = try CanonicalJSON.encode(payload)
        print(String(data: canonicalOutput, encoding: .utf8)!, terminator: "")
        exit(0)

    } catch {
        fputs("ENVELOPE_INVALID\n", stderr)
        exit(2)
    }
}

func convertRawToDER(_ raw: Data) throws -> Data {
    guard raw.count == 64 else {
        throw CryptoSignError.signingFailed
    }

    var r = raw[0..<32]
    var s = raw[32..<64]

    while r.count > 1 && r.first == 0x00 && r[1] < 0x80 {
        r = r.dropFirst()
    }
    if r.first! >= 0x80 {
        r = Data([0x00]) + r
    }

    while s.count > 1 && s.first == 0x00 && s[1] < 0x80 {
        s = s.dropFirst()
    }
    if s.first! >= 0x80 {
        s = Data([0x00]) + s
    }

    var der = Data()
    der.append(0x30)
    der.append(UInt8(4 + r.count + s.count))
    der.append(0x02)
    der.append(UInt8(r.count))
    der.append(r)
    der.append(0x02)
    der.append(UInt8(s.count))
    der.append(s)

    return der
}

let args = CommandLine.arguments

guard args.count > 1 else {
    printUsage()
    exit(1)
}

do {
    switch args[1] {
    case "keygen":
        generateKeypair()

    case "sign":
        guard args.count == 4 else {
            printUsage()
            throw CryptoSignError.invalidArguments
        }
        try signMessage(args[2], args[3])

    case "verify":
        guard args.count == 5 else {
            printUsage()
            throw CryptoSignError.invalidArguments
        }
        try verifySignature(args[2], args[3], args[4])

    case "envelope":
        guard args.count == 6 else {
            printUsage()
            throw CryptoSignError.invalidArguments
        }
        try createEnvelope(args[2], args[3], args[4], args[5])

    case "envelope-decrypt":
        var recipientPrivHex: String?
        var envelopeBase64: String?

        var i = 2
        while i < args.count {
            if args[i] == "--recipient-priv-hex" && i + 1 < args.count {
                recipientPrivHex = args[i + 1]
                i += 2
            } else if args[i] == "--envelope-base64" && i + 1 < args.count {
                envelopeBase64 = args[i + 1]
                i += 2
            } else {
                i += 1
            }
        }

        guard let priv = recipientPrivHex, let envelope = envelopeBase64 else {
            fputs("Missing required arguments: --recipient-priv-hex and --envelope-base64\n", stderr)
            exit(1)
        }

        decryptEnvelope(privHex: priv, envelopeBase64: envelope)

    default:
        printUsage()
        throw CryptoSignError.invalidArguments
    }
} catch {
    print("Error: \(error)")
    exit(1)
}
