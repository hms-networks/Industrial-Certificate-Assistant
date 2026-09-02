# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path


WINDOWS_INSTALL = r'''# Run in PowerShell. Administrative approval is required.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Join-Path $Here "root-ca.cert.pem"
$Intermediate = Join-Path $Here "intermediate-ca.cert.pem"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Administrator privileges are required before modifying the Local Computer certificate stores. Rerun PowerShell as Administrator."
  exit 1
}
if (-not (Test-Path $Root)) { throw "Root CA certificate was not found: $Root" }
Write-Host "Root CA SHA-256 fingerprint:"
& certutil.exe -hashfile $Root SHA256
$answer = Read-Host "Install this root CA for all users? Type INSTALL to continue"
if ($answer -cne "INSTALL") { throw "Installation cancelled." }
Import-Certificate -FilePath $Root -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
if (Test-Path $Intermediate) {
    Import-Certificate -FilePath $Intermediate -CertStoreLocation Cert:\LocalMachine\CA | Out-Null
}
Write-Host "Certificate trust installed successfully. Restart all browsers."
'''

WINDOWS_REMOVE = r'''# Run in PowerShell. Administrative approval is required.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($item in @(@("root-ca.cert.pem", "Root"), @("intermediate-ca.cert.pem", "CA"))) {
    $path = Join-Path $Here $item[0]
    if (Test-Path $path) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path)
        $target = "Cert:\LocalMachine\$($item[1])\$($cert.Thumbprint)"
        if (Test-Path $target) { Remove-Item $target -Force }
    }
}
Write-Host "Certificate trust removed. Restart all browsers."
'''

LINUX_INSTALL = r'''#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/root-ca.cert.pem"
INTERMEDIATE="$HERE/intermediate-ca.cert.pem"
openssl x509 -in "$ROOT" -noout -subject -issuer -fingerprint -sha256
read -r -p "Install this root CA system-wide? Type INSTALL to continue: " answer
[[ "$answer" == "INSTALL" ]] || { echo "Installation cancelled."; exit 1; }
if command -v update-ca-trust >/dev/null 2>&1; then
  sudo install -m 0644 "$ROOT" /etc/pki/ca-trust/source/anchors/industrial-root-ca.pem
  sudo update-ca-trust
elif command -v update-ca-certificates >/dev/null 2>&1; then
  sudo install -m 0644 "$ROOT" /usr/local/share/ca-certificates/industrial-root-ca.crt
  sudo update-ca-certificates
else
  echo "Unsupported system trust-store layout. Install the root CA manually." >&2
  exit 2
fi
echo "Certificate trust installed. Restart all browsers."
'''

LINUX_REMOVE = r'''#!/usr/bin/env bash
set -euo pipefail
if command -v update-ca-trust >/dev/null 2>&1; then
  sudo rm -f /etc/pki/ca-trust/source/anchors/industrial-root-ca.pem
  sudo update-ca-trust
elif command -v update-ca-certificates >/dev/null 2>&1; then
  sudo rm -f /usr/local/share/ca-certificates/industrial-root-ca.crt
  sudo update-ca-certificates --fresh
else
  echo "Unsupported system trust-store layout." >&2
  exit 2
fi
echo "Certificate trust removed. Restart all browsers."
'''


def create_trust_bundle(destination: Path, root_certificate: Path, intermediate_certificate: Path | None = None) -> dict[str, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    root_out = destination / "root-ca.cert.pem"
    root_out.write_bytes(root_certificate.read_bytes())
    if intermediate_certificate:
        (destination / "intermediate-ca.cert.pem").write_bytes(intermediate_certificate.read_bytes())
    scripts = {
        "windows_install": destination / "install-trust-windows.ps1",
        "windows_remove": destination / "remove-trust-windows.ps1",
        "linux_install": destination / "install-trust-linux.sh",
        "linux_remove": destination / "remove-trust-linux.sh",
    }
    scripts["windows_install"].write_text(WINDOWS_INSTALL, encoding="utf-8-sig")
    scripts["windows_remove"].write_text(WINDOWS_REMOVE, encoding="utf-8-sig")
    scripts["linux_install"].write_text(LINUX_INSTALL, encoding="utf-8")
    scripts["linux_remove"].write_text(LINUX_REMOVE, encoding="utf-8")
    scripts["linux_install"].chmod(0o755); scripts["linux_remove"].chmod(0o755)
    return scripts
