# Windows Completion Steps

This WinUI 3 app was scaffolded on macOS. The following steps must be completed **on a Windows machine with Visual Studio 2022**.

---

## Prerequisites

- **Windows 10** version 1903+ or **Windows 11**
- **Visual Studio 2022** (17.8+) with:
  - .NET desktop development workload
  - Windows App SDK C# Templates
  - Windows Application Packaging Project extension
- **.NET 10 SDK**
- **Windows SDK** 10.0.22621.0+

---

## Step 1: Open Solution in Visual Studio

```powershell
# From desktop/windows/
start Sigil.Windows.sln
```

Visual Studio will prompt to install missing workloads if needed.

---

## Step 2: Restore NuGet Packages

Visual Studio should auto-restore. If not:

```powershell
dotnet restore
```

**Expected packages:**
- Microsoft.WindowsAppSDK 1.7.x
- Microsoft.Windows.SDK.BuildTools
- Microsoft.Extensions.DependencyInjection
- Microsoft.Extensions.Logging

---

## Step 3: Implement Windows Hello Integration

**File:** `src/Sigil.Windows.App/WindowsHelloKeyProvider.cs`

**Current state:** Stub with `NotImplementedException`

**Implementation:**

```csharp
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Sigil.Windows.Core.Abstractions;

public sealed class WindowsHelloKeyProvider : IDeviceKeyProvider
{
    public async Task<DeviceKeyHandle> GenerateKeypairAsync(CancellationToken ct = default)
    {
        // Check if Windows Hello is available
        var available = await KeyCredentialManager.IsSupportedAsync();
        if (!available)
        {
            throw new NotSupportedException("Windows Hello not available");
        }

        // Request key creation with biometric prompt
        var keyName = $"Sigil_{Guid.NewGuid()}";
        var result = await KeyCredentialManager.RequestCreateAsync(
            keyName,
            KeyCredentialCreationOption.ReplaceExisting);

        if (result.Status != KeyCredentialStatus.Success)
        {
            throw new InvalidOperationException($"Key creation failed: {result.Status}");
        }

        // Export public key (compressed P-256)
        var publicKey = result.Credential.RetrievePublicKey(CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
        var compressedKey = CompressPublicKey(publicKey);

        return new DeviceKeyHandle(keyName, compressedKey);
    }

    public async Task<byte[]> SignAsync(DeviceKeyHandle handle, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        // Open existing key (triggers biometric prompt)
        var result = await KeyCredentialManager.OpenAsync(handle.KeyName);
        if (result.Status != KeyCredentialStatus.Success)
        {
            throw new InvalidOperationException($"Key open failed: {result.Status}");
        }

        // Hash payload (SHA-256)
        var hashAlg = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
        var buffer = CryptographicBuffer.CreateFromByteArray(payload.ToArray());
        var hash = hashAlg.HashData(buffer);

        // Sign with biometric verification
        var signResult = await result.Credential.RequestSignAsync(hash);
        if (signResult.Status != KeyCredentialStatus.Success)
        {
            throw new InvalidOperationException($"Signing failed: {signResult.Status}");
        }

        // Convert DER signature to raw R||S (64 bytes)
        CryptographicBuffer.CopyToByteArray(signResult.Result, out var derSignature);
        return ConvertDerToRaw(derSignature);
    }

    private static byte[] CompressPublicKey(IBuffer publicKeyBuffer)
    {
        // Extract X and Y coordinates from X.509 SPKI
        // ... (implementation omitted for brevity - see test provider for example)
    }

    private static byte[] ConvertDerToRaw(byte[] derSignature)
    {
        // Parse DER and convert to 64-byte R||S
        // ... (see TestDeviceKeyProvider.cs for implementation)
    }
}
```

**Reference:** See `tests/Sigil.Windows.Core.Tests/TestDeviceKeyProvider.cs` for DER parsing logic.

---

## Step 4: Add App Icons

**Location:** `src/Sigil.Windows.App/Assets/`

Generate icons at required scales (see `Assets/README.md` for full list):

1. Design 1024×1024 master icon
2. Use [App Icon Generator](https://www.appicongenerator.com/) or Photoshop to export all scales
3. Place in `Assets/` directory
4. Update `Sigil.Windows.App.csproj` `<Content Include="Assets\**">` ensures they're included

**Minimum required:**
- Square44x44Logo (tile icon)
- Wide310x150Logo (wide tile)
- SplashScreen (620×300 base)
- StoreLogo (50×50 base)

---

## Step 5: Build and Run

```powershell
# Debug build
dotnet build -c Debug

# Run
dotnet run --project src\Sigil.Windows.App\Sigil.Windows.App.csproj

# Or press F5 in Visual Studio
```

**Expected behavior:**
- App window opens with "Sigil Auth" title
- Status shows "Disconnected"
- Click "Connect" → prompts for Windows Hello
- Connects to relay at ws://192.168.0.192:30080/ws
- Shows fingerprint after successful auth

---

## Step 6: MSIX Packaging

### Option A: Visual Studio

1. Right-click `Sigil.Windows.Package` project → **Publish** → **Create App Packages**
2. Select **Sideloading**
3. Choose signing certificate (or create test cert)
4. Build → produces `.msix` in `src\Sigil.Windows.Package\AppPackages\`

### Option B: Command Line

```powershell
# Build package project
msbuild src\Sigil.Windows.Package\Sigil.Windows.Package.wapproj /p:Configuration=Release /p:Platform=x64

# Package is output to:
# src\Sigil.Windows.Package\AppPackages\Sigil.Windows.Package_0.1.0.0_x64_Test\
```

---

## Step 7: Code Signing (Production)

For production MSIX, sign with EV certificate:

```powershell
# Sign MSIX
SignTool sign /fd SHA256 /a /f MyCert.pfx /p <password> Sigil.Windows_0.1.0.0_x64.msix

# Verify signature
SignTool verify /pa Sigil.Windows_0.1.0.0_x64.msix
```

**Certificate requirements:**
- EV code signing certificate (hardware token from DigiCert, Sectigo, etc.)
- Or standard code signing cert for sideload (users must trust publisher)

See `packaging/sign.ps1` for automation script.

---

## Step 8: Install and Test

```powershell
# Install MSIX (requires admin or Developer Mode enabled)
Add-AppxPackage -Path .\Sigil.Windows_0.1.0.0_x64.msix

# Launch from Start menu or:
start shell:AppsFolder\com.wagmilabs.sigil_<hash>!App

# Uninstall
Remove-AppxPackage -Package com.wagmilabs.sigil_<version>
```

---

## Common Issues

### Build Error: "Windows App SDK not found"

**Solution:** Install via NuGet Package Manager or:
```powershell
dotnet add package Microsoft.WindowsAppSDK --version 1.7.250107002
```

### Runtime Error: "Windows Hello not available"

**Causes:**
- TPM not enabled in BIOS
- Windows Hello not set up (Settings → Accounts → Sign-in options)
- Running in VM without TPM passthrough

**Solution:** Enable TPM, set up PIN or biometric in Windows Hello settings.

### MSIX Install Fails: "Untrusted publisher"

**Solutions:**
- Enable Developer Mode (Settings → Privacy & Security → For developers)
- **OR** Install signing certificate to Trusted People store
- **OR** Use EV certificate (auto-trusted)

### App Crashes on Launch

**Check:**
- Windows SDK version matches `TargetPlatformVersion` in `.csproj`
- All NuGet packages restored
- No missing DLLs (run `dumpbin /dependents Sigil.Windows.App.exe`)

---

## Verification Checklist

- [ ] Solution builds with zero warnings
- [ ] App launches and shows main window
- [ ] Windows Hello prompts on first connection
- [ ] Connects to relay successfully
- [ ] Shows fingerprint after auth
- [ ] Push notifications display (test via relay)
- [ ] Disconnect works cleanly
- [ ] MSIX packages without errors
- [ ] Signed MSIX installs from double-click
- [ ] App listed in Start menu
- [ ] Uninstall removes cleanly

---

## Next Steps (Production)

1. **Store submission:** Create Partner Center account, upload signed MSIX
2. **Auto-updates:** Configure Microsoft Store update channel
3. **Telemetry:** Add Application Insights or similar
4. **Settings:** Add UI for relay URL configuration
5. **Notifications:** Implement full approval dialog with action context display
6. **MPA:** Multi-party authorization flows (M-of-N approval)
7. **i18n:** Localization support (use shared-i18n/ strings)

---

## Support

**Build issues:** Check `desktop/windows/README.md`
**Protocol questions:** See `working/protocol-spec.md`
**GitHub issues:** https://github.com/sigilauth/desktop/issues
