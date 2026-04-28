# Changelog

All notable changes to the Sigil Auth macOS desktop app will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-26

### Added
- WebSocket relay client with full challenge-response authentication flow
- RelayClient actor with async/await API for relay connections
- Secure Enclave integration for hardware-backed ECDSA P-256 key storage
- YubiKey integration for external security key support
- Pictogram fingerprint visualization (64-emoji visual representation)
- Complete SwiftUI interface with 5 main views:
  - ApprovalView: Biometric authentication approval screen
  - PairingView: Server pairing flow
  - PictogramView: Visual fingerprint display
  - QuickApproveView: Pending approvals list
  - ServerListView: Paired servers management
- Comprehensive accessibility support (VoiceOver, Dynamic Type, keyboard navigation)
- Shared DesignSystem module for consistent UI styling
- Localization infrastructure (FTL-ready, English baseline)
- Test suite: 19 unit tests (LowS signatures, Pictogram)
- Integration test suite: 11 tests for relay protocol validation (skipped by default)

### Fixed
- Double-hashing bug in ECDSA signature generation (was hashing challenge twice)
- XCTest signal 5 (SIGTRAP) crash caused by DispatchSemaphore in test class initialization
- Actor isolation warnings in async setUp/tearDown methods
- Timer leak in ApprovalView (proper cleanup in onDisappear)
- Invalid weak capture on struct (ApprovalView is value type)
- LAContext recreation inefficiency (now reuses single instance)
- Array bounds crash risk in pictogram emoji lookup (added guard check)
- Force cast crash risk on NSApp.keyWindow (now uses optional unwrap)

### Changed
- Migrated from imperative UIKit patterns to declarative SwiftUI
- Replaced DispatchSemaphore with Swift concurrency (async/await)
- Integration tests now skipped by default (require live relay instance)
- Test suite separated from workaround script (native swift test support)

### Security
- Private keys never leave Secure Enclave / hardware security module
- Biometric gate on every signing operation (no silent background auth)
- Mutual authentication (both device and server sign challenges)
- Domain-separated ECDSA signing (prevents signature reuse across contexts)

## [0.0.1] - 2026-04-20

### Added
- Initial macOS desktop app scaffold
- Swift Package Manager configuration
- Basic project structure

[Unreleased]: https://github.com/sigilauth/sigil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sigilauth/sigil/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/sigilauth/sigil/releases/tag/v0.0.1
