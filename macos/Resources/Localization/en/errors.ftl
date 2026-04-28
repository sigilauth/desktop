# Errors Domain — User-Facing Error Messages
# English source strings — authored by @cora per voice guide §3-4
# Key naming: error-{CODE} where CODE matches OpenAPI enum (snake_case → kebab-case)
# These are user-facing. No jargon, no internal error details.

## API Error Codes (from /api/openapi.yaml components/schemas/Error)
# Keys map 1:1 with server error codes

error-invalid-signature = Verification failed. The response could not be verified.
error-invalid-public-key = Invalid device key format. Try re-registering this device.
error-challenge-not-found = Request not found. It may have expired.
error-challenge-expired = This request has expired. Ask them to send a new one.
error-challenge-already-used = Already responded to this request.
error-fingerprint-mismatch = Device fingerprint does not match. Re-register this device.
error-decryption-failed = Decryption failed. The encrypted data could not be read.
error-timestamp-invalid = Request timestamp is invalid. Check your device clock.
error-relay-unavailable = Push service is temporarily unavailable. Try again.
error-unauthorized = Authentication failed. Check your credentials.
error-rate-limited = Too many requests. Please wait a moment and try again.

## Network Errors (client-side)
# Connection and timeout failures detected by app
# Per voice guide §1.4: empathetic, acknowledge frustration, offer fix

error-network = No connection. Tap to retry when you're back online.
error-timeout = Request timed out. Tap to try again.
error-server-unreachable = Couldn't reach { $serverName }. They may be having issues.
error-server-unreachable-generic = Couldn't reach the server. They may be having issues.
error-offline = You appear to be offline. Connect to respond.

## Pairing Errors (client-side + server)
# QR code, pairing code, deep link failures

error-invalid-qr = Invalid QR code. Scan a Sigil Auth registration code.
error-invalid-pairing-code = That code didn't work. Check the code and try again.
error-pairing-code-expired = This code has expired. Get a new one from the setup page.
error-pairing-code-attempts = Too many attempts. Request a new code.
error-pairing-code-used = This pairing code has already been used.

## Registration Errors (client-side + server)
# Device registration failures

error-attestation-failed = Device attestation failed. This device may not be supported.
error-already-registered = This device is already registered with this server.
error-registration-rejected = Registration was rejected. Contact your administrator.

## Biometric Errors (client-side)
# Face ID, Touch ID, fingerprint failures

error-biometric-failed = Couldn't verify. Try again.
error-biometric-cancelled = Cancelled.
error-biometric-not-available = Biometric authentication isn't available on this device.
error-biometric-not-enrolled = Set up { $biometricType } in your device settings to continue.
error-biometric-not-enrolled-generic = Set up Face ID or fingerprint in your device settings to continue.
error-biometric-lockout = Too many attempts. Wait a moment and try again.

## Hardware Key Errors (client-side)
# YubiKey, Titan, FIDO2 hardware key failures

error-hardware-key-not-found = Security key not detected. Insert or tap your key.
error-hardware-key-failed = Security key verification failed. Try again.
error-hardware-key-timeout = Security key timed out. Try again.

## MPA Errors (server)
# Multi-party authorization failures

error-mpa-not-found = Authorization request not found.
error-mpa-timeout = Authorization request timed out. Start a new request.
error-mpa-rejected = Authorization was rejected.
error-mpa-quorum-failed = Not enough approvals received before timeout.

## Decrypt Errors (server)
# Secure decrypt failures

error-decrypt-not-found = Decrypt request not found.
error-decrypt-expired = Decrypt request expired.
error-decrypt-rejected = Decrypt request was rejected.

## Push Notification Errors
# Permission and delivery failures

error-push-permission-denied = Turn on notifications in Settings to receive approval requests.
error-push-delivery-failed = Couldn't deliver notification. Check your connection.

## Device State Errors
# Device registration state issues

error-device-removed = This device was removed from { $serverName }. Re-register to continue.
error-device-not-registered = This server isn't registered on your device.

## Server Errors (generic)
# Server-side failures (no internal details exposed)

error-server = Something went wrong on the server. Please try again.
error-maintenance = Service is temporarily unavailable for maintenance.
