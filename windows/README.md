# Sigil Auth — Windows Desktop

> Hardware-backed ECDSA P-256 authentication for Windows 10+

Cross-platform .NET Windows desktop application for Sigil Auth strong authentication system. Uses Windows Hello / TPM for hardware-backed key storage.

---

## Use as NuGet Package

The core WebSocket client is available as a NuGet package for .NET integrators:

```bash
dotnet add package Sigil.Auth.Client
```

**Quick example:**

```csharp
using Sigil.Windows.Core.Network;
using Sigil.Windows.Core.Abstractions;

// Implement IDeviceKeyProvider for your platform
var keyProvider = new YourKeyProvider();
var client = new WebSocketChallengeListener(keyProvider, logger);

client.ConnectionStateChanged += (s, e) => 
    Console.WriteLine($"State: {e.NewState}");

await client.ConnectAsync(new Uri("wss://relay.sigilauth.com/ws"));
Console.WriteLine($"Fingerprint: {client.Fingerprint}");
```

**Full documentation:** See [src/Sigil.Windows.Core/README.md](src/Sigil.Windows.Core/README.md) for complete API reference and examples.

---

## Prerequisites

### Required

- **Windows 10** version 1903+ or **Windows 11**
- **Visual Studio 2022** (v17.8+) with:
  - .NET desktop development workload
  - Windows App SDK C# Templates component
- **OR** **VS Code** with:
  - [C# Dev Kit extension](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.csdevkit)
  - [.NET Install Tool extension](https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.vscode-dotnet-runtime)
- **.NET 10 SDK** ([download](https://dotnet.microsoft.com/download/dotnet/10.0))
- **Windows SDK** 10.0.22621.0+ (included with Visual Studio or install standalone)

### Optional (for packaging and distribution)

- **Windows Application Packaging Project** Visual Studio extension (for MSIX)
- **Code signing certificate** (`.pfx` file or installed in Windows cert store)
- **MakeAppx.exe** and **SignTool.exe** (included with Windows SDK)

---

## Project Structure

```
windows/
├── src/
│   └── Sigil.Windows.Core/          # Platform-agnostic core library
│       ├── Abstractions/             # Interfaces (IDeviceKeyProvider, etc.)
│       ├── Network/                  # WebSocket relay client
│       └── Protocol/                 # DTO types (auth messages)
├── tests/
│   └── Sigil.Windows.Core.Tests/    # xUnit integration + unit tests
├── packaging/                        # Code signing + MSIX scripts
│   ├── sign.ps1                      # Authenticode signing script
│   ├── package.ps1                   # MSIX packaging script
│   └── README.md                     # Detailed packaging docs
├── Directory.Build.props             # Shared build configuration
└── Sigil.Windows.sln                 # Solution file
```

---

## Build Commands

All commands run from `windows/` directory unless specified.

### 1. Restore NuGet packages

```powershell
dotnet restore
```

### 2. Build solution

```powershell
# Debug build
dotnet build

# Release build
dotnet build -c Release
```

**Note:** .NET 10 is required (net10.0 target framework). Projects will not build on .NET 8 or earlier.

### 3. Run tests

```powershell
# All tests (integration + unit)
dotnet test

# Integration tests only (requires doppler relay running)
dotnet test --filter "FullyQualifiedName~Integration"

# Unit tests only (no network dependencies)
dotnet test --filter "FullyQualifiedName~UnitTests"
```

**Integration test endpoint:** `ws://192.168.0.192:30080/ws` (doppler cluster relay via NodePort). Tests will timeout if relay unreachable.

### 4. Run application (when UI added)

```powershell
dotnet run --project src/Sigil.Windows.App/Sigil.Windows.App.csproj
```

---

## Code Signing

### Setup

1. Obtain a code signing certificate (EV or standard):
   - **EV certificate:** Hardware token (USB) from DigiCert, Sectigo, etc.
   - **Standard certificate:** `.pfx` file with private key

2. Install certificate (if using `.pfx`):
   ```powershell
   # Import to CurrentUser\My store
   Import-PfxCertificate -FilePath .\MyCert.pfx -CertStoreLocation Cert:\CurrentUser\My
   ```

3. Set environment variable:
   ```powershell
   # For .pfx file
   $env:CODE_SIGN_PFX_PATH = "C:\path\to\cert.pfx"
   $env:CODE_SIGN_PFX_PASSWORD = "password"

   # OR for certificate in store
   $env:CODE_SIGN_THUMBPRINT = "ABC123..."
   ```

### Sign binaries

```powershell
cd packaging
.\sign.ps1 -BinaryPath ..\src\Sigil.Windows.App\bin\Release\net10.0\Sigil.Windows.App.exe
```

See `packaging/README.md` for full signing documentation.

---

## MSIX Packaging

### Manual packaging

1. Build in Release mode:
   ```powershell
   dotnet build -c Release
   ```

2. Create MSIX package:
   ```powershell
   cd packaging
   .\package.ps1 -Version 1.0.0
   ```

3. Output: `packaging\output\Sigil.Windows_1.0.0.0_x64.msix`

### Package contents

- Application binaries (`.exe`, `.dll`)
- WinUI 3 runtime dependencies
- App manifest (`AppxManifest.xml`)
- Assets (app icon, splash screen)

### Install MSIX locally

```powershell
# Add as trusted app (requires admin)
Add-AppxPackage -Path .\Sigil.Windows_1.0.0.0_x64.msix
```

**Note:** Self-signed packages require enabling Developer Mode or installing the signing certificate to Trusted People store.

---

## Distribution

### GitHub Releases

1. Tag release: `git tag windows/v1.0.0 && git push origin windows/v1.0.0`
2. Attach signed MSIX to GitHub Release
3. Users download `.msix` and double-click to install

### Microsoft Store

1. Create Partner Center account
2. Reserve app name: "Sigil Auth"
3. Upload `.msix` via Partner Center dashboard
4. Submit for certification (1-3 business days)

**Store benefits:** Automatic updates, no code signing cert needed (Microsoft signs), wider distribution.

---

## Development Workflow

### Visual Studio 2022

1. Open `Sigil.Windows.sln`
2. Set `Sigil.Windows.App` as startup project (when UI added)
3. Press F5 to build + run
4. Tests visible in Test Explorer (View → Test Explorer)

### VS Code

1. Open `windows/` folder
2. Install recommended extensions (C# Dev Kit)
3. Terminal: `dotnet build`
4. Terminal: `dotnet test`
5. Debug: F5 (uses `.vscode/launch.json` if configured)

---

## Common Issues

### Build fails: "net10.0 not found"

- Install .NET 10 SDK: https://dotnet.microsoft.com/download/dotnet/10.0
- Verify: `dotnet --list-sdks` shows 10.x.x

### Tests timeout

- Integration tests require doppler relay at `ws://192.168.0.192:30080/ws`
- If relay unreachable, tests fail after 30-60s timeout
- Run unit tests only: `dotnet test --filter "FullyQualifiedName~UnitTests"`

### Signing fails: "SignTool not found"

- Install Windows SDK 10.0.22621.0+
- Add to PATH: `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\`

### MSIX install blocked: "Untrusted publisher"

- Enable Developer Mode: Settings → Privacy & Security → For developers
- **OR** install signing certificate to Trusted People store

---

## CI/CD

See `.github/workflows/windows-build.yml` (when added) for automated:
- Build on `push` to `main` or `windows/**` branches
- Test execution (unit tests only; integration tests require cluster access)
- MSIX packaging on tagged releases (`windows/v*`)
- Artifact upload to GitHub Releases

**Secrets required:**
- `CODE_SIGN_PFX_BASE64`: Base64-encoded `.pfx` file
- `CODE_SIGN_PFX_PASSWORD`: Certificate password

---

## Architecture

### Core library (`Sigil.Windows.Core`)

Platform-agnostic .NET 10 library. No WinUI/WPF dependencies. Cross-platform compatible (runs on macOS/Linux for testing).

**Key components:**
- `WebSocketChallengeListener`: Relay client with exponential backoff reconnection
- `IDeviceKeyProvider`: Abstraction for hardware key storage (TPM, Windows Hello)
- Protocol DTOs: JSON-serialized messages (auth challenge, auth response, etc.)

### App project (`Sigil.Windows.App`) — TODO

WinUI 3 desktop application. Depends on Core library. Windows-only (uses Windows App SDK 1.7+).

**Key components:**
- UI views (login, device management, notifications)
- Windows Hello integration (`Windows.Security.Credentials.UI`)
- Background task for push notifications

---

## Security

- **Hardware keys:** Private keys stored in TPM / Windows Hello vault (never exported)
- **Code signing:** All releases Authenticode-signed to prevent tampering
- **MSIX sandboxing:** App runs in AppContainer with restricted capabilities
- **TLS:** WebSocket relay connections over `wss://` (TLS 1.3)

---

## License

AGPL-3.0 — see `/LICENSE` for full text.

API specifications (OpenAPI, JSON schemas) under Apache-2.0.

---

## Support

- **Issues:** https://github.com/sigilauth/desktop/issues
- **Docs:** https://docs.sigilauth.com (TODO)
- **Email:** support@sigilauth.com
