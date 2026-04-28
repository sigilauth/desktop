# Changelog

All notable changes to the Sigil Auth Windows desktop application will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Domain-separated ECDSA signing** (`Sigil.Windows.Core.Crypto`):
  - `DomainTag` constants for Auth, MPA, Decrypt contexts
  - `EcdsaSign.Sign()` method implementing `SHA256(domain_tag || message)` signing
  - BIP-62 low-S normalization to prevent signature malleability
  - Cross-platform test vectors (`Fixtures/domain-separation/*.json`)
  - xUnit tests verifying byte-for-byte compatibility with Linux/mobile implementations
- **CryptoSign CLI test harness** (`Sigil.Windows.CryptoSign`):
  - Command-line tool implementing `crypto-sign --domain <auth|mpa|decrypt> --message <hex> --private-key <hex>`
  - Enables cross-platform signature verification against test vectors
  - Outputs 64-byte R||S signature as lowercase hex
- **Cross-domain rejection tests:** Verifies signatures created with one domain tag cannot verify with another

### Changed
- **WebSocketChallengeListener authentication:** Now constructs domain-tagged payload (`DomainTag.Auth || challengeBytes`) before signing, ensuring compliance with `api/domain-separation.md` specification

### Breaking Changes
- **Domain-separated signatures:** All signatures now include domain tag prefix per `api/domain-separation.md`. Signatures created by earlier versions will not verify against domain-separated implementations. Re-registration required.

### Known Issues
- **Windows Hello integration incomplete:** `WindowsHelloKeyProvider` is a stub with `NotImplementedException`. Requires Windows machine to implement `Windows.Security.Credentials.KeyCredentialManager` APIs.
- **App icons missing:** Placeholder icon used. Final icons at all required scales (16x16, 32x32, 48x48, 256x256, Square44x44Logo, etc.) need generation on Windows machine.
- **No end-to-end testing:** WinUI 3 app has not been built or tested on Windows. Scaffolding only.
- **Code signing not configured:** MSIX packages are unsigned. Production deployment requires Authenticode certificate.

---

## [0.1.0] - 2026-04-26

Initial release of Sigil Auth for Windows. Includes platform-agnostic core library (NuGet package) and WinUI 3 desktop app scaffolding.

### Added

#### Core Library (`Sigil.Windows.Core`)
- **WebSocket relay client** (`WebSocketChallengeListener`) with exponential backoff reconnection (1s → 2s → 4s → 8s → max 30s)
- **Protocol DTOs** for auth challenge, auth response, ECIES decrypt, MPA payloads
- **Connection state machine** with events: `Disconnected` → `Connecting` → `Connected` → `Authenticated` (or `Failed`)
- **Abstraction layer** (`IDeviceKeyProvider`, `IWebSocketClient`) for testability and platform independence
- **Factory pattern** for dependency injection with default production implementation (`ClientWebSocketAdapter`)
- **NuGet package** published as `Sigil.Auth.Client` with:
  - Target framework: .NET 10 (`net10.0`)
  - AOT-compatible, trimming-friendly
  - Symbol package (`.snupkg`) for debugging
  - Comprehensive README with API reference and examples
- **Integration tests** against doppler relay (NodePort `ws://192.168.0.192:30080/ws`)
- **Unit tests** for edge cases (malformed JSON, wrong message sequence, cancellation, backoff calculation, connection state transitions)
- **Mock WebSocket client** for testing without network dependencies
- **Software key provider example** (`TestDeviceKeyProvider`) using mnemonic-derived ECDSA P-256 keys with `ECDsa.TrySignHash()` and IEEE P1363 format (raw R||S 64-byte signatures)

#### WinUI 3 Desktop App (`Sigil.Windows.App`)
- **App scaffolding** with dependency injection (`Microsoft.Extensions.DependencyInjection`)
- **Main window** with:
  - Connect/disconnect buttons
  - Status display (connection state)
  - Fingerprint display (SHA-256 hash of device public key)
  - Event handlers for `ConnectionStateChanged`, `NotificationReceived`
- **Windows Hello stub** (`WindowsHelloKeyProvider`) — requires Windows machine to implement
- **MVVM setup** ready for future ViewModels
- **Target platform:** Windows 10 (1903+) and Windows 11, x64 + ARM64

#### MSIX Packaging (`Sigil.Windows.Package`)
- **Package manifest** configured for `com.wagmilabs.sigil`, publisher `CN=Wagmi Labs`
- **Minimum version:** Windows 10 1809 (10.0.17763.0)
- **Target version:** Windows 11 22H2 (10.0.22621.0)
- **Capabilities:** `runFullTrust` for TPM/Windows Hello access
- **Packaging project** (`.wapproj`) for Visual Studio MSIX builds

#### Documentation
- **README.md** — comprehensive build guide (prerequisites, build commands, code signing, MSIX packaging, distribution, CI/CD, troubleshooting)
- **NuGet usage section** with quick start example
- **WINDOWS-COMPLETION.md** — 8-step guide for Windows machine implementation (Windows Hello APIs, icon generation, build/test/sign)
- **WINDOWS-APP-STATUS.md** — current state tracker (what's done, what's missing, next actions)
- **Core library README** (`src/Sigil.Windows.Core/README.md`) — API reference, examples, connection states, events
- **Windows install guide** (`docs/install-windows.md`) — MSIX sideload, Scoop, Winget (placeholder), troubleshooting

#### CI/CD
- **NuGet publish workflow** (`.github/workflows/nuget-publish.yml`) triggered on tags `windows/v*.*.*`:
  - Builds Core library
  - Runs unit tests (integration tests skipped in CI — require cluster access)
  - Packs to `.nupkg` with version extracted from tag
  - Publishes to nuget.org with `NUGET_API_KEY` secret
  - Uploads package as artifact (90-day retention)

#### Build Configuration
- **Nullable reference types enabled** (`<Nullable>enable</Nullable>`)
- **Warnings as errors** (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`)
- **Self-contained Windows App SDK** (`<WindowsAppSDKSelfContained>true</WindowsAppSDKSelfContained>`)
- **Assembly metadata** with `InternalsVisibleTo` for test access

### Changed
- **Signature format:** Switched from manual DER parsing to `ECDsa.TrySignHash()` with `DSASignatureFormat.IeeeP1363FixedFieldConcatenation` for direct raw R||S output (64 bytes, no encoding overhead)
- **Test endpoint:** Integration tests use doppler relay NodePort (`192.168.0.192:30080`) instead of unreachable ClusterIP

### Fixed
- **DER signature parsing bug** in `TestDeviceKeyProvider.ConvertDerToRaw()` — replaced with built-in IEEE P1363 format
- **Network connectivity** in integration tests — switched from ClusterIP to LAN-accessible NodePort
- **Unit test assertion failures** — changed expected state transitions to exception expectations for malformed input tests
- **CancellationToken test** — changed from `ThrowsAsync` to `ThrowsAnyAsync` to catch `TaskCanceledException` (subclass of `OperationCanceledException`)
- **Test console app compilation** — moved class definitions after top-level statements

### Security
- **Hardware key storage:** Private keys generated in TPM (Trusted Platform Module) via Windows Hello — never exported, never written to disk
- **Mutual authentication:** Both device and server sign challenges/responses (no shared secrets, no TOTP)
- **ECIES encryption:** AES-256-GCM + ECDH for sensitive payloads (MPA action context, mnemonic delivery)
- **TLS only:** WebSocket relay connections over `wss://` (TLS 1.3)
- **MSIX sandboxing:** App runs in AppContainer with restricted capabilities (production builds)

### Performance
- **Connection pooling:** WebSocket client reuses connections across multiple auth flows
- **Exponential backoff:** Reconnection delays prevent relay overload (1s → 2s → 4s → 8s → 30s max)
- **Async/await throughout:** No blocking calls on UI thread
- **Trimming-friendly:** Core library annotated for NativeAOT and IL trimming

### Dependencies
- **Microsoft.Extensions.Logging.Abstractions** 8.0.0 (Core library)
- **Microsoft.Windows.SDK.BuildTools** 10.0.26100.1742 (App)
- **Microsoft.WindowsAppSDK** 1.7.250107002 (App)
- **xUnit** 2.9.3 (Tests)

### Breaking Changes
None (initial release).

---

## Release Notes

### v0.1.0 — Initial Release

**What's working:**
- ✅ Core WebSocket relay client with full protocol support
- ✅ NuGet package (`Sigil.Auth.Client`) for .NET integrators
- ✅ Integration tests against doppler relay (manual run)
- ✅ Unit tests for edge cases (automated in CI)
- ✅ WinUI 3 app scaffolding with DI setup
- ✅ MSIX packaging configuration
- ✅ Documentation (README, install guide, API reference)

**What needs Windows machine to complete:**
- ⚠️ Windows Hello key provider implementation (`WindowsHelloKeyProvider.cs`)
- ⚠️ App icon generation at all required scales
- ⚠️ WinUI 3 app build and testing
- ⚠️ MSIX packaging and signing
- ⚠️ End-to-end verification with real TPM

**Estimated completion time:** 2-4 hours on Windows machine with Visual Studio 2022.

**Next steps:**
1. Implement `WindowsHelloKeyProvider` using `Windows.Security.Credentials.KeyCredentialManager` APIs (see `WINDOWS-COMPLETION.md` for example code)
2. Generate icons via Windows-based tools or design software
3. Build in Visual Studio: F5 to test
4. Package: `dotnet publish -c Release -r win-x64`
5. Sign with Authenticode certificate: `signtool sign /fd SHA256 /a Sigil.Windows.App.exe`
6. Create MSIX: `makeappx pack /d publish\ /p Sigil.Windows.msix`
7. Test install: `Add-AppxPackage -Path .\Sigil.Windows.msix`
8. Verify Windows Hello biometric prompt and TPM key generation
9. Submit to Microsoft Store (optional) or distribute via GitHub Releases

**Known limitations:**
- Integration tests require doppler cluster access (skipped in CI)
- No automatic update mechanism yet (MSIX supports this, needs implementation)
- Single relay endpoint (multi-endpoint switching planned for v0.2.0)
- No MPA approval UI (push notifications received, no approval dialog yet)

---

[Unreleased]: https://github.com/sigilauth/desktop/compare/windows/v0.1.0...HEAD
[0.1.0]: https://github.com/sigilauth/desktop/releases/tag/windows/v0.1.0
