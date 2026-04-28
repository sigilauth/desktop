# Windows Desktop Packaging

Scripts for code signing and MSIX packaging of Sigil Auth Windows desktop app.

---

## Prerequisites

### 1. Windows SDK

Install Windows SDK 10 (required for `signtool.exe` and `makeappx.exe`):
- Download: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
- Or via Visual Studio Installer → Individual Components → Windows SDK

### 2. Code Signing Certificate

You need an Authenticode code signing certificate. Options:

**Option A: Certificate Store (Recommended for CI)**
- Install certificate to Windows Certificate Store
- Note the SHA-1 thumbprint

**Option B: .pfx File**
- Export certificate as .pfx with private key
- Store securely (DO NOT commit to git)

---

## Code Signing Setup

### Environment Variables

Set **one** of these pairs:

**For .pfx file:**
```powershell
$env:SIGIL_CERT_PATH = "C:\path\to\wagmi-labs.pfx"
$env:SIGIL_CERT_PASSWORD = "your-pfx-password"
```

**For certificate store:**
```powershell
$env:SIGIL_CERT_THUMBPRINT = "ABCDEF1234567890..." # SHA-1 thumbprint
```

### Find Certificate Thumbprint

```powershell
# List all code signing certificates
Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert

# Copy the Thumbprint value (40-character hex string)
```

---

## Building & Packaging

### Step 1: Publish the App

```powershell
cd desktop\windows

# For x64
dotnet publish src\Sigil.Windows.App\Sigil.Windows.App.csproj `
    -c Release `
    -r win-x64 `
    --self-contained

# For ARM64
dotnet publish src\Sigil.Windows.App\Sigil.Windows.App.csproj `
    -c Release `
    -r win-arm64 `
    --self-contained
```

### Step 2: Create Signed MSIX

```powershell
# Set certificate (see above)
$env:SIGIL_CERT_PATH = "C:\path\to\cert.pfx"
$env:SIGIL_CERT_PASSWORD = "password"

# Package and sign
.\packaging\package.ps1 -Configuration Release -Platform x64
```

Output: `artifacts\SigilAuth-x64.msix`

---

## Manual Signing (Individual Files)

To sign individual executables or DLLs:

```powershell
.\packaging\sign.ps1 -TargetPath "path\to\file.exe"
```

---

## CI Integration (GitHub Actions)

**Example workflow step:**

```yaml
- name: Setup Code Signing
  shell: powershell
  run: |
    $certBytes = [Convert]::FromBase64String("${{ secrets.AUTHENTICODE_CERT_BASE64 }}")
    $certPath = "${{ runner.temp }}\wagmi-labs.pfx"
    [IO.File]::WriteAllBytes($certPath, $certBytes)
    echo "SIGIL_CERT_PATH=$certPath" >> $env:GITHUB_ENV
    echo "SIGIL_CERT_PASSWORD=${{ secrets.AUTHENTICODE_CERT_PASSWORD }}" >> $env:GITHUB_ENV

- name: Build and Package
  shell: powershell
  run: |
    dotnet publish -c Release -r win-x64 --self-contained
    .\packaging\package.ps1 -Configuration Release -Platform x64

- name: Upload MSIX
  uses: actions/upload-artifact@v4
  with:
    name: SigilAuth-Windows-x64
    path: artifacts\SigilAuth-x64.msix
```

**Required secrets:**
- `AUTHENTICODE_CERT_BASE64`: Base64-encoded .pfx file
- `AUTHENTICODE_CERT_PASSWORD`: .pfx password

---

## Verification

After signing, verify the signature:

```powershell
# The sign.ps1 script automatically verifies, but you can also manually check:
signtool verify /pa /v artifacts\SigilAuth-x64.msix
```

Expected output: `Successfully verified`

---

## SmartScreen

To avoid SmartScreen warnings on fresh Windows machines:

1. **Use an EV (Extended Validation) certificate** — instant reputation
2. **OR build reputation** — 1000s of downloads + zero malware reports over weeks

For MVP launch, EV cert recommended.

---

## Troubleshooting

### "Certificate not found"
- Check thumbprint is correct (40 hex chars, no spaces)
- Ensure certificate is in `Cert:\CurrentUser\My` store
- Verify certificate has Code Signing EKU

### "signtool.exe not found"
- Install Windows SDK 10
- Ensure SDK bin directory is in PATH, or script will auto-detect

### "Timestamp server unavailable"
- DigiCert timestamp server is default: `http://timestamp.digicert.com`
- If unavailable, try `http://timestamp.sectigo.com`
- Edit `sign.ps1` `/tr` parameter

---

## Security Notes

- **NEVER commit .pfx files to git**
- **NEVER commit plaintext passwords**
- Use GitHub Secrets or Azure Key Vault for CI
- Rotate certificates before expiry (typically 1-3 years)

---

## Next Steps

1. Obtain Authenticode certificate (Kaity to provide)
2. Test signing on a Windows machine
3. Verify MSIX installs without SmartScreen warnings
4. Add to CI pipeline (B12 work block)
