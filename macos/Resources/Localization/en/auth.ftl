# Auth Domain — Registration and Biometric Flows
# English source strings — authored by @cora per voice guide §3-4
# Key naming: kebab-case, grouped by flow

## Onboarding
# Context: First-time app launch, 3 screens per voice guide §4.1

onboarding-screen1-title = Your keys, your hardware
onboarding-screen1-body = Sigil uses your device's secure chip. Your private key never leaves this device.

onboarding-screen2-title = Tap to approve
onboarding-screen2-body = When a server needs you, you'll get a notification. Approve with your face, fingerprint, or security key.

onboarding-screen3-title = Ready when you are
onboarding-screen3-body = Scan a QR code or enter a pairing code to register with your first server.

onboarding-get-started = Get Started
onboarding-skip = Skip

## Registration Flow
# Context: First-time device setup, user scans QR or enters pairing code

registration-title = Register Device
registration-scan-qr = Scan QR Code
registration-enter-code = Enter Pairing Code
registration-verify-server = Verify Server Identity
# Developer note: pictogram confirmation is security-critical — user must match visual
registration-confirm-pictogram = Confirm this pictogram matches what your admin showed you
registration-success = Device Registered
registration-share-pictogram = Share this with your admin to verify your enrollment

## Pairing Code Entry
# Context: 8-digit numeric code entry (camera-free pairing)

pairing-code-title = Enter Pairing Code
pairing-code-placeholder = 8-digit code
pairing-code-submit = Connect

## Server Verification
# Context: User confirms server identity before trusting

server-verify-title = Verify Server Identity
server-verify-name = Server: { $serverName }
server-verify-url = URL: { $serverUrl }
server-verify-warning = Verify this pictogram matches what your admin showed you before continuing.
server-verify-confirmed = Verified - Continue
server-verify-cancel = Cancel

## Biometric Prompts
# Context: System biometric prompt customization
# Developer note: $biometricType is platform-specific (Face ID, Touch ID, fingerprint)

biometric-prompt-approve = Approve with { $biometricType }
biometric-prompt-hardware-key = Use hardware key
# Platform-specific biometric type names (do not translate brand names)
biometric-type-face-id = Face ID
biometric-type-touch-id = Touch ID
biometric-type-fingerprint = fingerprint
biometric-type-windows-hello = Windows Hello

## Hardware Key
# Context: YubiKey, Titan, or other FIDO2 hardware key prompts

hardware-key-prompt = Insert or tap your security key
hardware-key-waiting = Waiting for security key...
hardware-key-success = Security key verified
hardware-key-failed = Security key not recognized. Try again.
