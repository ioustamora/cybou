# Deploy script for Cybou on Windows
# Creates a distributable package with all dependencies

Write-Host "=== Cybou Deployment Script ===" -ForegroundColor Cyan

$QtPath = "C:\Qt\6.10.0\mingw_64"
$BuildDir = "build"
$DeployDir = "cybou-release"

# Check if build exists
if (-not (Test-Path "$BuildDir\cybou.exe")) {
    Write-Host "Error: cybou.exe not found. Build first!" -ForegroundColor Red
    exit 1
}

# Clean and create deploy directory
if (Test-Path $DeployDir) {
    Remove-Item -Recurse -Force $DeployDir
}
New-Item -ItemType Directory -Path $DeployDir | Out-Null

# Copy executable
Write-Host "Copying executable..." -ForegroundColor Green
Copy-Item "$BuildDir\cybou.exe" $DeployDir

# Set up environment and run windeployqt
Write-Host "Deploying Qt dependencies..." -ForegroundColor Green
$env:PATH = "$QtPath\bin;C:\msys64\mingw64\bin;$env:PATH"
& "$QtPath\bin\windeployqt.exe" --qmldir qml "$DeployDir\cybou.exe"

# Copy additional DLLs from MSYS2
Write-Host "Copying liboqs and OpenSSL..." -ForegroundColor Green
$msysDlls = @(
    "C:\msys64\mingw64\bin\liboqs.dll",
    "C:\msys64\mingw64\bin\libcrypto-3-x64.dll",
    "C:\msys64\mingw64\bin\libssl-3-x64.dll"
)

foreach ($dll in $msysDlls) {
    if (Test-Path $dll) {
        Copy-Item $dll $DeployDir -ErrorAction SilentlyContinue
    }
}

# Create README for distribution
$readmeContent = @"
# Cybou - Post-Quantum Encryption Tool

## Installation
Simply extract all files to a folder and run cybou.exe

## Features
- BIP-39 Mnemonic Generation
- Post-Quantum Encryption (Kyber-1024)
- Digital Signatures (ML-DSA-65)
- File & Text Encryption
- Cross-platform compatible

## System Requirements
- Windows 10/11 64-bit
- No additional dependencies needed (all included)

## Getting Started
1. Run cybou.exe
2. Generate or import a mnemonic phrase
3. Start encrypting files and text!

For more information: https://github.com/ioustamora/cybou
"@

Set-Content -Path "$DeployDir\README.txt" -Value $readmeContent

Write-Host "`n=== Deployment Complete! ===" -ForegroundColor Green
Write-Host "Package created in: $DeployDir" -ForegroundColor Cyan
Write-Host "Package size: $((Get-ChildItem $DeployDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB) MB" -ForegroundColor Cyan

Write-Host "`nTo create ZIP:" -ForegroundColor Yellow
Write-Host "  Compress-Archive -Path $DeployDir -DestinationPath cybou-windows-x64.zip" -ForegroundColor Gray
