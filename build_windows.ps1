$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is required but was not found in PATH."
}

# Install dependencies
python -m pip install -r requirements.txt || exit 1

# Check if rcedit is installed and install if needed
python -m pip show rcedit *> $null
if ($LASTEXITCODE -ne 0) {
    python -m pip install rcedit
}

# Clean up previous builds
if (Test-Path ".\build") {
    Remove-Item ".\build" -Recurse -Force
}
if (Test-Path ".\dist") {
    Remove-Item ".\dist" -Recurse -Force
}
if (Test-Path ".\IndustrialCertificateAssistant.spec") {
    Remove-Item ".\IndustrialCertificateAssistant.spec" -Force
}

# Setup build arguments
$extraArgs = @()
if (Test-Path ".\vendor\openssl\windows\openssl.exe") {
    $extraArgs += @("--add-binary", "vendor\openssl\windows;vendor\openssl\windows")
} elseif (Test-Path ".\openssl_binaries\windows\openssl.exe") {
    $extraArgs += @("--add-binary", "openssl_binaries\windows;openssl_binaries\windows")
}

$iconArg = @()
$iconDataArg = @()
$bannerDataArg = @()
$splashArg = @()
$iconName = $null

if (Test-Path ".\HMS.ico") {
    $iconName = "HMS.ico"
} elseif (Test-Path ".\hms.ico") {
    $iconName = "hms.ico"
}

if ($iconName) {
    $iconArg = @("--icon", $iconName)
    $iconDataArg = @("--add-data", "$iconName;.")
} else {
    Write-Warning "No icon file found (expected HMS.ico or hms.ico)."
}

if (Test-Path ".\HMS_banner.png") {
    $bannerDataArg = @("--add-data", "HMS_banner.png;.")
    $splashArg = @("--splash", "HMS_banner.png")
} elseif (Test-Path ".\HMS_Banner.png") {
    $bannerDataArg = @("--add-data", "HMS_Banner.png;.")
    $splashArg = @("--splash", "HMS_Banner.png")
}

# Build the executable
python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name IndustrialCertificateAssistant `
    @extraArgs `
    @iconDataArg `
    @bannerDataArg `
    @iconArg `
    @splashArg `
    app.py

Write-Host "Built dist\IndustrialCertificateAssistant.exe"
Pop-Location
