# Code Signing Script for Sigil Auth Windows Desktop
#
# Prerequisites:
# - Windows SDK (signtool.exe)
# - Authenticode certificate (.pfx or from cert store)
#
# Environment Variables:
# - SIGIL_CERT_PATH: Path to .pfx file (optional if using cert store)
# - SIGIL_CERT_PASSWORD: Password for .pfx file
# - SIGIL_CERT_THUMBPRINT: Certificate thumbprint (for cert store signing)
#
# Usage:
#   .\sign.ps1 -TargetPath "path\to\file.exe"
#   .\sign.ps1 -TargetPath "path\to\file.dll"
#   .\sign.ps1 -TargetPath "path\to\file.msix"

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetPath,

    [Parameter(Mandatory=$false)]
    [string]$CertPath = $env:SIGIL_CERT_PATH,

    [Parameter(Mandatory=$false)]
    [string]$CertPassword = $env:SIGIL_CERT_PASSWORD,

    [Parameter(Mandatory=$false)]
    [string]$CertThumbprint = $env:SIGIL_CERT_THUMBPRINT
)

$ErrorActionPreference = "Stop"

# Validate input file exists
if (-not (Test-Path $TargetPath)) {
    Write-Error "Target file not found: $TargetPath"
    exit 1
}

# Find signtool.exe
$signtoolPaths = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
)

$signtool = $signtoolPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $signtool) {
    Write-Error "signtool.exe not found. Install Windows SDK."
    exit 1
}

Write-Host "Using signtool: $signtool" -ForegroundColor Cyan

# Determine signing method
if ($CertPath) {
    # Sign with .pfx file
    Write-Host "Signing with certificate file: $CertPath" -ForegroundColor Green

    if (-not (Test-Path $CertPath)) {
        Write-Error "Certificate file not found: $CertPath"
        exit 1
    }

    if (-not $CertPassword) {
        Write-Error "SIGIL_CERT_PASSWORD environment variable required for .pfx signing"
        exit 1
    }

    $signArgs = @(
        "sign",
        "/f", $CertPath,
        "/p", $CertPassword,
        "/fd", "SHA256",
        "/tr", "http://timestamp.digicert.com",
        "/td", "SHA256",
        "/v",
        $TargetPath
    )

} elseif ($CertThumbprint) {
    # Sign with certificate from store
    Write-Host "Signing with certificate from store: $CertThumbprint" -ForegroundColor Green

    $signArgs = @(
        "sign",
        "/sha1", $CertThumbprint,
        "/fd", "SHA256",
        "/tr", "http://timestamp.digicert.com",
        "/td", "SHA256",
        "/v",
        $TargetPath
    )

} else {
    Write-Error @"
No signing certificate specified. Set one of:
  - SIGIL_CERT_PATH + SIGIL_CERT_PASSWORD (for .pfx file)
  - SIGIL_CERT_THUMBPRINT (for certificate in store)

Example:
  `$env:SIGIL_CERT_PATH = "C:\certs\wagmi-labs.pfx"
  `$env:SIGIL_CERT_PASSWORD = "your-password"
  .\sign.ps1 -TargetPath "bin\Release\SigilAuth.exe"
"@
    exit 1
}

# Execute signtool
Write-Host "Signing: $TargetPath" -ForegroundColor Yellow
& $signtool @signArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Successfully signed: $TargetPath" -ForegroundColor Green

# Verify signature
Write-Host "Verifying signature..." -ForegroundColor Cyan
& $signtool verify /pa /v $TargetPath

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Signature verification failed"
} else {
    Write-Host "Signature verified successfully" -ForegroundColor Green
}
