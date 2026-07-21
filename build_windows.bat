@echo off
rem Copyright 2026 HMS Networks
rem SPDX-License-Identifier: Apache-2.0
setlocal
python -m pip install -r requirements.txt || exit /b 1
set "EXTRA="
if exist "vendor\openssl\windows\openssl.exe" (
    for %%F in (LICENSE.txt NOTICE.txt VERSION.txt SHA256SUMS.txt) do (
        if not exist "vendor\openssl\windows\%%F" (
            echo ERROR: Bundled OpenSSL requires vendor\openssl\windows\%%F
            exit /b 1
        )
    )
    set "EXTRA=--add-binary vendor\openssl\windows;vendor\openssl\windows"
)
python -m PyInstaller --noconfirm --clean --windowed --onefile --name IndustrialCertificateAssistant %EXTRA% app.py
