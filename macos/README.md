# Sigil Auth — macOS Desktop App (B7)

Native macOS app for Sigil Auth MVP. Hardware-backed PKI authentication with Secure Enclave and YubiKey support.

## Platform

- **macOS:** 12.0+ (Monterey)
- **Architecture:** Apple Silicon (M1+) with Secure Enclave, Intel with YubiKey fallback
- **Tech Stack:** SwiftUI + AppKit, Swift 5.9+
- **Build:** Swift Package Manager

## Features

- ✅ Secure Enclave keypair generation (M1+ Macs)
- ✅ Touch ID biometric gate on every signing operation
- ⏳ YubiKey FIDO2 fallback (Intel Macs)
- ⏳ Menubar icon with quick-approve flyouts
- ⏳ Keyboard shortcuts (Cmd+Shift+A, etc.)
- ⏳ Multi-window support
- ⏳ VoiceOver accessible (Aria §7)
- ⏳ Fluent i18n (7 P0 locales)
- ⏳ Code-signed + notarized (via CI B12)

## Build

```bash
# Build library + tests
swift build

# Run tests
swift test

# Generate Xcode project (optional)
swift package generate-xcodeproj
open SigilAuth.xcodeproj
```

## Test Coverage

**Target:** 75% line coverage, 65% branch coverage (Maren §10)

**Current Status:** 🟢 Pictogram derivation: 100% (TDD complete)

## TDD Progress

Following strict TDD per D5:

1. ✅ **Pictogram derivation** — Tests written first against `/api/test-vectors/pictogram.json`, implementation follows
2. ⏳ **ECDSA signing** — Tests against `/api/test-vectors/ecdsa.json`
3. ⏳ **Keychain storage** — Integration tests for Secure Enclave + Keychain
4. ⏳ **Challenge handling** — Tests against OpenAPI contract
5. ⏳ **UI flows** — XCUITest for approval, pairing, settings

## Security (Knox Top 5)

1. ✅ **Hardware key extraction infeasible** — Secure Enclave on M1+, YubiKey on Intel
2. ✅ **Biometric gate on every sign** — LocalAuthentication with `biometryCurrentSet`
3. ✅ **Device self-authentication** — Public key sent with response, fingerprint verified
4. ✅ **Plaintext challenges over TLS** — D2 locked
5. ✅ **Stateless server** — Not our concern (B1)

## Accessibility (Aria §7)

**15 Blocking Criteria (macOS-specific):**

- ⏳ Keyboard navigation (Tab, Cmd shortcuts)
- ⏳ Focus indicators (2px outline, 3:1 contrast)
- ⏳ VoiceOver labels on all interactive elements
- ⏳ VoiceOver rotor custom actions
- ⏳ Dynamic Type (text scales to 200%)
- ⏳ Reduce Motion support

## Directory Structure

```
desktop/macos/
├── Package.swift              # Swift Package Manager manifest
├── Sources/
│   ├── SigilAuth/            # Core library
│   │   ├── SigilAuth.swift   # Module entry point
│   │   └── Crypto/
│   │       ├── Pictogram.swift       # ✅ TDD complete
│   │       ├── SecureEnclave.swift   # ⏳ Next
│   │       └── ECDSA.swift           # ⏳ Next
│   └── SigilAuthApp/         # macOS app executable
│       └── main.swift
├── Tests/
│   └── SigilAuthTests/
│       ├── PictogramTests.swift      # ✅ TDD complete
│       └── TestVectors/              # Copied from /api/test-vectors/
└── README.md                 # This file
```

## Coordination

- **@nova (iOS):** Reusing Secure Enclave + LocalAuthentication patterns from nova-mobile-platform-spec.md §2
- **@knox:** Awaiting guidance on Intel Mac fallback (YubiKey mandatory or software keystore allowed?)
- **@iris:** Need menubar icon design (16×16, 32×32 retina)
- **@cascade:** Keychain patterns confirmed in cascade-data-architecture.md §5.1

## Blocking Dependencies

- ✅ **B0 (Protocol Spec)** — Green light received
- ⏳ **B1 (Go Server)** — Need running server for integration tests
- ⏳ **B2 (Push Relay)** — WebSocket fallback testing (desktop doesn't use push)
- ⏳ **B15 (Fluent Catalog)** — Need shared string catalog for i18n

## Next Steps

1. ✅ Scaffold Swift Package
2. ✅ Write pictogram tests (TDD)
3. ✅ Implement pictogram derivation
4. ⏳ Write ECDSA tests
5. ⏳ Implement Secure Enclave signing
6. ⏳ Write Keychain tests
7. ⏳ Implement Keychain wrapper

## Acceptance Criteria (B7)

- [ ] Runs on macOS 12+
- [ ] Secure Enclave on M1+, YubiKey on Intel
- [ ] Keyboard-only nav covers all flows
- [ ] Notarized binary (CI B12 does signing)
- [ ] 75/65 test coverage

## License

AGPL-3.0 (copyleft) — API specifications are Apache-2.0

---

**Status:** 🟢 TDD in progress — Pictogram complete, ECDSA next
**Owner:** Nova (macOS instance)
**Block:** B7
**Started:** 2026-04-23
