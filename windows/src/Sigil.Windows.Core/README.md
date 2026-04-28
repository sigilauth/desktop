# Sigil.Auth.Client

> Cross-platform .NET WebSocket client for Sigil Auth relay

[![NuGet](https://img.shields.io/nuget/v/Sigil.Auth.Client.svg)](https://www.nuget.org/packages/Sigil.Auth.Client/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://github.com/sigilauth/desktop/blob/main/LICENSE)

Hardware-backed ECDSA P-256 authentication with push notifications. Supports Windows Hello, macOS Secure Enclave, and software keys for testing.

## Features

- **WebSocket relay client** with automatic reconnection (exponential backoff)
- **Challenge-response authentication** (ECDSA P-256 signatures)
- **Push notifications** via relay server
- **Connection state management** with events
- **AOT-compatible** (Native AOT, trimming, ReadyToRun)
- **Cross-platform** (.NET 10+, runs on Windows, macOS, Linux)

## Installation

```bash
dotnet add package Sigil.Auth.Client
```

**Note:** Despite the `Sigil.Windows.Core` namespace, this package is fully cross-platform and runs on Windows, macOS, and Linux.

## Quick Start

```csharp
using Sigil.Windows.Core.Abstractions;
using Sigil.Windows.Core.Network;
using Microsoft.Extensions.Logging;

// 1. Implement IDeviceKeyProvider for your platform
// (use Windows Hello, Secure Enclave, or software keys)
var keyProvider = new YourDeviceKeyProvider();

// 2. Create logger (or use NullLogger for production)
var logger = LoggerFactory.Create(b => b.AddConsole())
    .CreateLogger<WebSocketChallengeListener>();

// 3. Create client
var client = new WebSocketChallengeListener(keyProvider, logger);

// 4. Subscribe to events
client.ConnectionStateChanged += (sender, e) =>
{
    Console.WriteLine($"State: {e.OldState} → {e.NewState}");
};

client.NotificationReceived += (sender, e) =>
{
    Console.WriteLine($"Notification: {e.Notification.Type}");
};

// 5. Connect to relay
await client.ConnectAsync(new Uri("wss://relay.sigilauth.com/ws"));

// 6. Check state and fingerprint
Console.WriteLine($"Connected: {client.State == ConnectionState.Connected}");
Console.WriteLine($"Fingerprint: {client.Fingerprint}");

// 7. Disconnect when done
await client.DisconnectAsync();
```

## IDeviceKeyProvider

Implement this interface to provide platform-specific key storage:

```csharp
public interface IDeviceKeyProvider
{
    Task<DeviceKeyHandle> GenerateKeypairAsync(CancellationToken cancellationToken = default);
    
    Task<byte[]> SignAsync(
        DeviceKeyHandle handle,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default);
}
```

### Example: Software Keys (Testing)

```csharp
using System.Security.Cryptography;

public class SoftwareKeyProvider : IDeviceKeyProvider
{
    private readonly Dictionary<string, ECDsa> _keys = new();

    public Task<DeviceKeyHandle> GenerateKeypairAsync(CancellationToken ct = default)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyName = Guid.NewGuid().ToString();
        _keys[keyName] = ecdsa;

        var compressedKey = CompressPublicKey(ecdsa.ExportParameters(false));
        return Task.FromResult(new DeviceKeyHandle(keyName, compressedKey));
    }

    public Task<byte[]> SignAsync(DeviceKeyHandle handle, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        var ecdsa = _keys[handle.KeyName];
        var hash = SHA256.HashData(payload.Span);
        
        var signature = new byte[64];
        ecdsa.TrySignHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out _);
        
        return Task.FromResult(signature);
    }

    private static byte[] CompressPublicKey(ECParameters parameters)
    {
        var compressed = new byte[33];
        compressed[0] = (byte)(parameters.Q.Y[^1] % 2 == 0 ? 0x02 : 0x03);
        parameters.Q.X.CopyTo(compressed.AsSpan(1));
        return compressed;
    }
}
```

### Production: Windows Hello

```csharp
using Windows.Security.Credentials;

// Windows-specific implementation using KeyCredentialManager
// (Full example in desktop/windows/src/Sigil.Windows.App/)
```

## Connection States

```csharp
public enum ConnectionState
{
    Disconnected,  // Not connected
    Connecting,    // TCP handshake in progress
    Authenticating,// Challenge-response in progress
    Connected,     // Authenticated and ready
    Reconnecting,  // Reconnect attempt (exponential backoff)
    Failed         // Connection failed (check events for error)
}
```

## Events

### ConnectionStateChanged

Fired on every state transition:

```csharp
client.ConnectionStateChanged += (sender, e) =>
{
    Console.WriteLine($"{e.OldState} → {e.NewState}");
    if (!string.IsNullOrEmpty(e.Error))
    {
        Console.WriteLine($"Error: {e.Error}");
    }
};
```

### NotificationReceived

Fired when server pushes a notification:

```csharp
client.NotificationReceived += (sender, e) =>
{
    var notification = e.Notification;
    Console.WriteLine($"Type: {notification.Type}");
    // Handle push notification (auth challenge, MPA request, etc.)
};
```

## Reconnection

Automatic reconnection with exponential backoff:

- Attempt 1: 1 second delay
- Attempt 2: 2 seconds
- Attempt 3: 4 seconds
- ...
- Attempt 10: 60 seconds (capped)

After 10 failed attempts, connection enters `Failed` state.

## Testing

See [`Sigil.Windows.Core.Tests`](../../tests/Sigil.Windows.Core.Tests/) for examples:

- **Integration tests:** Full handshake against live relay
- **Unit tests:** Mocked WebSocket for failure scenarios

```bash
# Run all tests
dotnet test

# Integration tests only (requires relay)
dotnet test --filter "FullyQualifiedName~Integration"

# Unit tests only (no network)
dotnet test --filter "FullyQualifiedName~UnitTests"
```

## License

AGPL-3.0 — see [LICENSE](https://github.com/sigilauth/desktop/blob/main/LICENSE)

API specifications (OpenAPI, JSON schemas) under Apache-2.0.

## Links

- **Documentation:** https://docs.sigilauth.com (TODO)
- **GitHub:** https://github.com/sigilauth/desktop
- **Issues:** https://github.com/sigilauth/desktop/issues
- **Website:** https://sigilauth.com
