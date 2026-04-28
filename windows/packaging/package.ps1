# MSIX Packaging Script for Sigil Auth Windows Desktop
#
# Creates an MSIX package from the published output
#
# Prerequisites:
# - Windows SDK (makeappx.exe)
# - Published output (via dotnet publish)
#
# Usage:
#   .\package.ps1 -Configuration Release -Platform x64

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "..\artifacts"
)

$ErrorActionPreference = "Stop"

$rootDir = Split-Path -Parent $PSScriptRoot
$projectDir = Join-Path $rootDir "src\Sigil.Windows.App"
$publishDir = Join-Path $projectDir "bin\$Configuration\net10.0-windows10.0.19041.0\win-$Platform\publish"
$msixPath = Join-Path $OutputDir "SigilAuth-$Platform.msix"

Write-Host "=== Sigil Auth MSIX Packaging ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration" -ForegroundColor Yellow
Write-Host "Platform: $Platform" -ForegroundColor Yellow
Write-Host "Publish Directory: $publishDir" -ForegroundColor Yellow
Write-Host "Output MSIX: $msixPath" -ForegroundColor Yellow

# Validate publish directory exists
if (-not (Test-Path $publishDir)) {
    Write-Error "Publish directory not found: $publishDir"
    Write-Host "Run 'dotnet publish -c $Configuration -r win-$Platform --self-contained' first" -ForegroundColor Red
    exit 1
}

# Create output directory
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Find makeappx.exe
$makeappxPaths = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x64\makeappx.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\makeappx.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22000.0\x64\makeappx.exe"
)

$makeappx = $makeappxPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $makeappx) {
    Write-Error "makeappx.exe not found. Install Windows SDK."
    exit 1
}

Write-Host "Using makeappx: $makeappx" -ForegroundColor Cyan

# Create MSIX package
Write-Host "Creating MSIX package..." -ForegroundColor Green
& $makeappx pack /d $publishDir /p $msixPath /o

if ($LASTEXITCODE -ne 0) {
    Write-Error "makeappx failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "MSIX package created: $msixPath" -ForegroundColor Green

# Sign the MSIX
Write-Host "Signing MSIX package..." -ForegroundColor Yellow
$signScript = Join-Path $PSScriptRoot "sign.ps1"
& $signScript -TargetPath $msixPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Signing failed"
    exit $LASTEXITCODE
}

# Display package info
$msixInfo = Get-Item $msixPath
Write-Host "`n=== Package Info ===" -ForegroundColor Cyan
Write-Host "Path: $($msixInfo.FullName)" -ForegroundColor White
Write-Host "Size: $([math]::Round($msixInfo.Length / 1MB, 2)) MB" -ForegroundColor White

Write-Host "`n✓ Package ready for distribution" -ForegroundColor Green
