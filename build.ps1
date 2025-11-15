# Build script for Cybou on Windows
# Requires: Qt 6.10.0, MSYS2 with liboqs and OpenSSL

Write-Host "=== Cybou Build Script ===" -ForegroundColor Cyan

# Set up environment
$env:PATH = "C:\Qt\6.10.0\mingw_64\bin;C:\Qt\Tools\mingw1310_64\bin;C:\Qt\Tools\Ninja;C:\msys64\mingw64\bin;$env:PATH"
$env:PKG_CONFIG_PATH = "C:\msys64\mingw64\lib\pkgconfig"

# Clean build directory (optional)
if ($args -contains "-clean") {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    if (Test-Path "build") {
        Remove-Item -Recurse -Force "build"
    }
}

# Create build directory
if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

# Configure
Write-Host "Configuring..." -ForegroundColor Green
cmake -B build -S . `
    -G "Ninja" `
    -DCMAKE_PREFIX_PATH="C:/Qt/6.10.0/mingw_64" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_CXX_COMPILER=g++ `
    -DOPENSSL_ROOT_DIR="C:/msys64/mingw64"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Configuration failed!" -ForegroundColor Red
    exit 1
}

# Build
Write-Host "Building..." -ForegroundColor Green
cmake --build build -j8

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Build Successful! ===" -ForegroundColor Green
Write-Host "Executables created:" -ForegroundColor Cyan
Get-ChildItem build\*.exe | ForEach-Object { Write-Host "  - $($_.Name)" }

# Run tests if requested
if ($args -contains "-test") {
    Write-Host "`n=== Running Tests ===" -ForegroundColor Cyan
    
    Write-Host "`nTest: Encryption..." -ForegroundColor Yellow
    & ".\build\test_encryption.exe"
    
    Write-Host "`nTest: Signatures..." -ForegroundColor Yellow
    & ".\build\test_signatures.exe"
}

# Run app if requested
if ($args -contains "-run") {
    Write-Host "`n=== Launching Cybou ===" -ForegroundColor Cyan
    $env:PATH = "C:\Qt\6.10.0\mingw_64\bin;$env:PATH"
    Start-Process -FilePath ".\build\cybou.exe"
}

Write-Host "`nUsage:" -ForegroundColor Gray
Write-Host "  .\build.ps1          - Build only" -ForegroundColor Gray
Write-Host "  .\build.ps1 -clean   - Clean and build" -ForegroundColor Gray
Write-Host "  .\build.ps1 -test    - Build and run tests" -ForegroundColor Gray
Write-Host "  .\build.ps1 -run     - Build and launch app" -ForegroundColor Gray
