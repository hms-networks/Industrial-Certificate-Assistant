@echo off
rem Copyright 2026 HMS Networks
rem SPDX-License-Identifier: Apache-2.0
setlocal

where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: Windows PowerShell was not found.
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_windows.ps1"
exit /b %ERRORLEVEL%
