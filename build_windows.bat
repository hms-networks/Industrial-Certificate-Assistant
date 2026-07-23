@echo off
rem Copyright 2026 HMS Networks
rem SPDX-License-Identifier: Apache-2.0
setlocal
python -m pip install -r requirements.txt || exit /b 1
set "EXTRA="
set "ICON_ARGS="
set "DATA_ARGS="
set "SPLASH_ARGS="
if exist "vendor\openssl\windows\openssl.exe" (
    for %%F in (LICENSE.txt NOTICE.txt VERSION.txt SHA256SUMS.txt) do (
        if not exist "vendor\openssl\windows\%%F" (
            echo ERROR: Bundled OpenSSL requires vendor\openssl\windows\%%F
            exit /b 1
        )
    )
    set "EXTRA=--add-binary vendor\openssl\windows;vendor\openssl\windows"
)
if exist "HMS.ico" (
    set "ICON_ARGS=--icon HMS.ico"
    set "DATA_ARGS=%DATA_ARGS% --add-data HMS.ico;."
) else if exist "hms.ico" (
    set "ICON_ARGS=--icon hms.ico"
    set "DATA_ARGS=%DATA_ARGS% --add-data hms.ico;."
)
if exist "HMS_banner.png" (
    set "SPLASH_ARGS=--splash HMS_banner.png"
    set "DATA_ARGS=%DATA_ARGS% --add-data HMS_banner.png;."
) else if exist "HMS_Banner.png" (
    set "SPLASH_ARGS=--splash HMS_Banner.png"
    set "DATA_ARGS=%DATA_ARGS% --add-data HMS_Banner.png;."
)
python -m PyInstaller --noconfirm --clean --windowed --onefile --name IndustrialCertificateAssistant %EXTRA% %DATA_ARGS% %ICON_ARGS% %SPLASH_ARGS% app.py
