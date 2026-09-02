$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$AppName = "IndustrialCertificateAssistant"
$AppVersion = "0.9.0"
$CompanyName = "HMS Networks"
$ProductName = "Industrial Certificate Assistant"
$Copyright = "Copyright 2026 HMS Networks"

Push-Location $PSScriptRoot
try {
    function Assert-File {
        param([Parameter(Mandatory)][string]$Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Required file was not found: $Path"
        }
    }

    function Find-Python {
        # Prefer python so an activated virtual environment is honored.
        foreach ($candidate in @("python", "py")) {
            if (Get-Command $candidate -ErrorAction SilentlyContinue) {
                return $candidate
            }
        }
        throw "Python was not found. Install Python 3 and ensure py.exe or python.exe is in PATH."
    }

    Assert-File ".\app.py"
    Assert-File ".\requirements.txt"
    Assert-File ".\pyi_rth_openssl.py"

    $Python = Find-Python
    & $Python -m pip install --disable-pip-version-check -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

    $OpenSslSource = $null
    if (Test-Path ".\vendor\openssl\windows\openssl.exe" -PathType Leaf) {
        $OpenSslSource = "vendor\openssl\windows"
    }
    elseif (Test-Path ".\openssl_binaries\windows\openssl.exe" -PathType Leaf) {
        $OpenSslSource = "openssl_binaries\windows"
    }
    else {
        throw "Bundled Windows OpenSSL was not found in vendor\openssl\windows or openssl_binaries\windows."
    }

    Assert-File ".\$OpenSslSource\openssl.exe"
    $ConfigCandidates = @(
        ".\$OpenSslSource\openssl.cnf",
        ".\$OpenSslSource\cnf\openssl.cnf"
    )
    if (-not ($ConfigCandidates | Where-Object { Test-Path $_ -PathType Leaf })) {
        throw "openssl.cnf was not found beneath $OpenSslSource."
    }

    if ($OpenSslSource -eq "vendor\openssl\windows") {
        foreach ($notice in @("LICENSE.txt", "NOTICE.txt", "VERSION.txt", "SHA256SUMS.txt")) {
            Assert-File ".\$OpenSslSource\$notice"
        }
    }

    Set-Content -LiteralPath ".\VERSION.txt" -Value $AppVersion -Encoding ascii -NoNewline

    $VersionParts = $AppVersion.Split(".")
    if ($VersionParts.Count -ne 3) { throw "AppVersion must use major.minor.patch format." }
    $FileVersion = "$($VersionParts[0]), $($VersionParts[1]), $($VersionParts[2]), 0"
    $VersionMetadata = @"
# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($FileVersion),
    prodvers=($FileVersion),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', '$CompanyName'),
         StringStruct('FileDescription', '$ProductName'),
         StringStruct('FileVersion', '$AppVersion.0'),
         StringStruct('InternalName', '$AppName'),
         StringStruct('LegalCopyright', '$Copyright'),
         StringStruct('OriginalFilename', '$AppName.exe'),
         StringStruct('ProductName', '$ProductName'),
         StringStruct('ProductVersion', '$AppVersion')]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@
    Set-Content -LiteralPath ".\windows_version_info.txt" -Value $VersionMetadata -Encoding utf8

    foreach ($directory in @(".\build", ".\dist")) {
        if (Test-Path $directory) { Remove-Item $directory -Recurse -Force }
    }
    if (Test-Path ".\$AppName.spec") { Remove-Item ".\$AppName.spec" -Force }

    $Arguments = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name", $AppName,
        "--version-file", ".\windows_version_info.txt",
        "--runtime-hook", ".\pyi_rth_openssl.py",
        "--add-binary", "$OpenSslSource;vendor\openssl\windows",
        "--add-data", "VERSION.txt;."
    )

    $IconName = if (Test-Path ".\HMS.ico") { "HMS.ico" } elseif (Test-Path ".\hms.ico") { "hms.ico" } else { $null }
    if ($IconName) {
        $Arguments += @("--icon", $IconName, "--add-data", "$IconName;.")
    }
    else {
        Write-Warning "No icon file found (expected HMS.ico or hms.ico)."
    }

    $BannerName = if (Test-Path ".\HMS_banner.png") { "HMS_banner.png" } elseif (Test-Path ".\HMS_Banner.png") { "HMS_Banner.png" } else { $null }
    if ($BannerName) {
        & $Python -c "from PIL import Image"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Installing Pillow to resize the PyInstaller splash image..."
            & $Python -m pip install --disable-pip-version-check "Pillow>=10,<13"
            if ($LASTEXITCODE -ne 0) { throw "Pillow installation failed." }
        }
        $Arguments += @("--splash", $BannerName, "--add-data", "$BannerName;.")
    }

    $Arguments += ".\app.py"
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }

    $Output = ".\dist\$AppName.exe"
    Assert-File $Output
    Write-Host "Built $Output (version $AppVersion)" -ForegroundColor Green
}
finally {
    Pop-Location
}