@echo off
rem Copyright 2026 HMS Networks
rem SPDX-License-Identifier: Apache-2.0
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"
set "SOURCE=openssl_binaries\windows"
set "TARGET=vendor\openssl\windows"
set "OPENSSL_EXE=%SOURCE%\openssl.exe"

echo ============================================================
echo  Industrial Certificate Assistant - OpenSSL Release Setup
echo ============================================================
echo.

if not exist "%OPENSSL_EXE%" (
    echo ERROR: %OPENSSL_EXE% was not found.
    echo Place this batch file in the repository root and try again.
    exit /b 1
)

for /f "tokens=2" %%V in ('"%OPENSSL_EXE%" version 2^>nul') do set "OPENSSL_VERSION=%%V"
if not defined OPENSSL_VERSION (
    echo ERROR: Unable to determine the OpenSSL version.
    exit /b 1
)

for /f "tokens=1 delims=." %%M in ("%OPENSSL_VERSION%") do set "OPENSSL_MAJOR=%%M"
set "CRYPTO_DLL=%SOURCE%\libcrypto-%OPENSSL_MAJOR%-x64.dll"
set "SSL_DLL=%SOURCE%\libssl-%OPENSSL_MAJOR%-x64.dll"

echo Detected OpenSSL %OPENSSL_VERSION% ^(major version %OPENSSL_MAJOR%^).
if not exist "%CRYPTO_DLL%" (
    echo ERROR: Matching runtime not found: %CRYPTO_DLL%
    exit /b 1
)
if not exist "%SSL_DLL%" (
    echo ERROR: Matching runtime not found: %SSL_DLL%
    exit /b 1
)

if not exist "%TARGET%" mkdir "%TARGET%" || exit /b 1

echo Copying the minimal matching runtime...
copy /y "%OPENSSL_EXE%" "%TARGET%\openssl.exe" >nul || exit /b 1
copy /y "%CRYPTO_DLL%" "%TARGET%\libcrypto-%OPENSSL_MAJOR%-x64.dll" >nul || exit /b 1
copy /y "%SSL_DLL%" "%TARGET%\libssl-%OPENSSL_MAJOR%-x64.dll" >nul || exit /b 1

if exist "%SOURCE%\openssl.cfg" (
    copy /y "%SOURCE%\openssl.cfg" "%TARGET%\openssl.cnf" >nul || exit /b 1
) else if exist "%SOURCE%\cnf\openssl.cnf" (
    copy /y "%SOURCE%\cnf\openssl.cnf" "%TARGET%\openssl.cnf" >nul || exit /b 1
) else (
    echo WARNING: No OpenSSL configuration file was found.
)

set "LICENSE_URL=https://raw.githubusercontent.com/openssl/openssl/openssl-%OPENSSL_VERSION%/LICENSE.txt"
echo Downloading the matching official OpenSSL license...
where curl.exe >nul 2>&1 || (
    echo ERROR: curl.exe is required to retrieve the official OpenSSL license.
    exit /b 1
)
curl.exe -fL --retry 3 --connect-timeout 20 "%LICENSE_URL%" -o "%TARGET%\LICENSE.txt"
if errorlevel 1 (
    echo ERROR: Could not download %LICENSE_URL%
    del /q "%TARGET%\LICENSE.txt" 2>nul
    exit /b 1
)
for %%F in ("%TARGET%\LICENSE.txt") do if %%~zF LSS 1000 (
    echo ERROR: Downloaded LICENSE.txt is unexpectedly small.
    exit /b 1
)

>"%TARGET%\NOTICE.txt" echo OpenSSL %OPENSSL_VERSION%
>>"%TARGET%\NOTICE.txt" echo Copyright OpenSSL Project Authors. All Rights Reserved.
>>"%TARGET%\NOTICE.txt" echo Licensed under the Apache License 2.0.
>>"%TARGET%\NOTICE.txt" echo Source and licensing information: https://openssl-library.org/
>>"%TARGET%\NOTICE.txt" echo License retrieved from: %LICENSE_URL%

>"%TARGET%\VERSION.txt" echo Bundled component: OpenSSL
>>"%TARGET%\VERSION.txt" echo Version: %OPENSSL_VERSION%
>>"%TARGET%\VERSION.txt" echo Platform: VC-WIN64A
>>"%TARGET%\VERSION.txt" echo Upstream source tag: https://github.com/openssl/openssl/tree/openssl-%OPENSSL_VERSION%
>>"%TARGET%\VERSION.txt" echo Prepared: %DATE% %TIME%
>>"%TARGET%\VERSION.txt" echo.
"%OPENSSL_EXE%" version -a >>"%TARGET%\VERSION.txt" 2>&1

echo Generating SHA-256 checksums...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$files = Get-ChildItem -LiteralPath '%TARGET%' -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' }; $lines = foreach ($file in $files) { $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant(); '{0}  {1}' -f $hash, $file.Name }; Set-Content -LiteralPath '%TARGET%\SHA256SUMS.txt' -Value $lines -Encoding ascii"
if errorlevel 1 exit /b 1

echo Updating .gitignore...
call :ensure_ignore ".pytest_cache/"
call :ensure_ignore "__pycache__/"
call :ensure_ignore "*.py[cod]"
call :ensure_ignore "build/"
call :ensure_ignore "dist/"
call :ensure_ignore "*.pem"
call :ensure_ignore "*.key"
call :ensure_ignore "*.csr"
call :ensure_ignore "*.crt"
call :ensure_ignore "*.cer"
call :ensure_ignore "*.pfx"
call :ensure_ignore "*.p12"
call :ensure_ignore "*.srl"
call :ensure_ignore "openssl_binaries/"
call :ensure_ignore "vendor/openssl/windows/*.exe"
call :ensure_ignore "vendor/openssl/windows/*.dll"

where git.exe >nul 2>&1
if not errorlevel 1 (
    git.exe rev-parse --is-inside-work-tree >nul 2>&1
    if not errorlevel 1 (
        echo Removing ignored development files from Git tracking only...
        git.exe rm -r --cached --ignore-unmatch .pytest_cache ica\__pycache__ tests\__pycache__ openssl_binaries >nul 2>&1
    )
)

echo Validating the portable OpenSSL runtime...
set "OPENSSL_CONF=%CD%\%TARGET%\openssl.cnf"
set "OPENSSL_MODULES=%CD%\%TARGET%"
"%TARGET%\openssl.exe" version -a || (
    echo ERROR: The prepared OpenSSL runtime failed to start.
    exit /b 1
)
"%TARGET%\openssl.exe" list -providers >nul || (
    echo ERROR: OpenSSL could not load its provider configuration.
    exit /b 1
)

echo.
echo Prepared runtime files:
dir /b "%TARGET%"
echo.
echo SUCCESS: OpenSSL %OPENSSL_VERSION% is ready under %TARGET%.
echo The original development tree remains locally under openssl_binaries.
echo.

set "CLEANUP="
set /p "CLEANUP=Delete local Python caches and OpenSSL sample PEM test keys now? [y/N]: "
if /i "%CLEANUP%"=="Y" (
    if exist ".pytest_cache" rmdir /s /q ".pytest_cache"
    if exist "ica\__pycache__" rmdir /s /q "ica\__pycache__"
    if exist "tests\__pycache__" rmdir /s /q "tests\__pycache__"
    if exist "%SOURCE%\PEM" rmdir /s /q "%SOURCE%\PEM"
    echo Local caches and sample PEM test keys removed.
) else (
    echo Local cleanup skipped. These paths are ignored by Git.
)

echo.
echo Review git status before committing:
echo   git status --short
exit /b 0

:ensure_ignore
findstr /x /l /c:%1 ".gitignore" >nul 2>&1
if errorlevel 1 >>".gitignore" echo %~1
exit /b 0

