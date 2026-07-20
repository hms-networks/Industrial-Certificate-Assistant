@echo off
setlocal
python -m pip install -r requirements.txt || exit /b 1
set "EXTRA="
if exist "vendor\openssl\windows\openssl.exe" set "EXTRA=--add-binary vendor\openssl\windows;vendor\openssl\windows"
python -m PyInstaller --noconfirm --clean --windowed --onefile --name IndustrialCertificateAssistant %EXTRA% app.py

