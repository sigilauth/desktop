/// Sigil Auth macOS Library
///
/// Hardware-backed PKI authentication for macOS.
/// Supports Secure Enclave (M1+) and YubiKey FIDO2.
///
/// ## Core Components
///
/// - ``Pictogram``: Device fingerprint visualization for verbal verification
/// - (More components to be added)
///
/// ## Platform Requirements
///
/// - macOS 12.0+ (Monterey)
/// - Secure Enclave (Apple Silicon) or YubiKey FIDO2 (Intel)
/// - Touch ID via LocalAuthentication
///
/// ## Decisions Compliance
///
/// - D2: Challenge wire format is plaintext over TLS
/// - D10: `pictogram_speakable` field uses spaces in JSON, hyphens in URLs
/// - D9: Biometric naming uses "Touch ID" / "Face ID" per Apple HIG

public struct SigilAuth {
    /// Library version
    public static let version = "0.1.0-alpha"

    /// Platform information
    public static let platform = "macos"

    /// Minimum supported macOS version
    public static let minimumOSVersion = "12.0"
}
