# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

"""Common folder layout for every certificate package ICA produces.

    <package>/
      README.txt   what this package is and what to copy where
      deploy/      copy to the device, server, or broker that owns the identity
      trust/       for the computers and clients that connect to it
      records/     ICA's own records for this issuance; never deployed
      archive/     earlier issuances, moved aside on reissue

Issue functions build their files at the package root and then call
organize_package(), which sorts them into the folders by file name.
"""

from __future__ import annotations

import json
import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path

DEPLOY = "deploy"
TRUST = "trust"
RECORDS = "records"
README = "README.txt"
ARCHIVE = "archive"
MANIFEST = "ica-package.json"
_RESERVED = {DEPLOY, TRUST, RECORDS, README, ARCHIVE}

_TRUST_NAMES = {"root-ca.pem", "intermediate-ca.pem", "ca-chain.pem"}

# One-line descriptions for the README. Keys are file names with any
# broker-/client-/server- role prefix removed.
_DESCRIPTIONS = {
    "certificate.pem": "Leaf certificate (PEM).",
    "certificate.der": "Leaf certificate (DER), for applications that require binary certificates.",
    "private-key.pem": "Private key for this identity. Secret: protect it and delete stray copies.",
    "private-key-rsa.pem": "Same private key in traditional PKCS#1 RSA form. Secret.",
    "fullchain.pem": "Leaf certificate followed by the issuing CA (root excluded), for servers that send a chain.",
    "certificate.pfx": "PKCS#12 bundle: certificate, private key, and CA chain (own password). Secret.",
    "root-ca.pem": "Root CA certificate: the trust anchor for this PKI.",
    "intermediate-ca.pem": "Issuing (intermediate) CA certificate.",
    "ca-chain.pem": "Issuing CA followed by root CA.",
    "install-trust-windows.ps1": "Installs the root and issuing CA into the Windows computer trust store.",
    "remove-trust-windows.ps1": "Removes that trust from Windows.",
    "install-trust-linux.sh": "Installs the root CA into the Linux system trust store.",
    "remove-trust-linux.sh": "Removes that trust from Linux.",
    "request.csr.pem": "Certificate signing request used for this issuance.",
    "server.csr": "Certificate signing request used for this issuance.",
    "certificate.ext": "X.509 extensions applied when the certificate was signed.",
    "certificate-report.txt": "Certificate details and validation results.",
    "ram-https.pem": "THE FILE TO UPLOAD to the RAM: certificate, issuing CA, and RSA private key. Secret.",
    "lighttpd-gau.pem": "Same content as ram-https.pem, under the file name the RAM web server uses. Secret.",
    "server.crt": "SixView Manager HTTPS certificate chain (leaf + issuing CA).",
    "server.key": "SixView Manager HTTPS private key. Secret.",
    "deploy-svm-certificate.sh": "Guarded installer for SixView Manager (backup, rollback, verification).",
    "mosquitto-tls.conf": "Mosquitto TLS listener configuration fragment.",
    "install-mosquitto-tls.sh": "Guarded installer for Mosquitto on Linux (backup and restore on failure).",
    "remove-mosquitto-tls.sh": "Removes the ICA Mosquitto TLS listener and its certificate files.",
    "verify-mqtt-tls.sh": "Connection test against the broker, run from a client machine.",
    "hivemq-keystore.p12": "HiveMQ keystore: broker key, certificate, and issuing CA (keystore password). Secret.",
    "hivemq-truststore.p12": "HiveMQ truststore: CAs used to verify client certificates (keystore password).",
    "hivemq-config.xml": "HiveMQ TLS listener; complete container config or block merged by the installer.",
    "install-hivemq-tls.sh": "Guarded installer for systemd-managed HiveMQ (backup, rollback, verification).",
    "verify-hivemq-tls.sh": "Connection and mutual-TLS test against the broker, run from a client machine.",
    "opcua-trust": "OPC UA application trust store: trusted/ root CA and its CRL, issuers/ issuing CA and its CRLs.",
    MANIFEST: "Machine-readable package description (profile, identity, serial, expiry).",
}

# Recognizes packages written before ica-package.json existed, by a file
# only that profile produces. Checked in order; certificate.pem alone is Crimson.
_PROFILE_SIGNATURES = (
    ("ram-https.pem", "ram_https"),
    ("server.crt", "sixview_manager_https_server"),
    ("hivemq-keystore.p12", "mqtt_broker"),
    ("mosquitto-tls.conf", "mqtt_broker"),
    ("broker-certificate.pem", "mqtt_broker"),
    ("client-certificate.pem", "mqtt_client"),
    ("certificate.pem", "flexedge_https"),
)


def _folder_for(name: str) -> str:
    if name.endswith((".csr.pem", ".csr", ".ext")) or name == "certificate-report.txt":
        return RECORDS
    if name in _TRUST_NAMES or name.startswith(("install-trust-", "remove-trust-", "verify-")):
        return TRUST
    return DEPLOY


def _describe(name: str) -> str:
    for prefix in ("broker-", "client-", "server-"):
        if name.startswith(prefix) and name[len(prefix):] in _DESCRIPTIONS:
            return _DESCRIPTIONS[name[len(prefix):]]
    return _DESCRIPTIONS.get(name, "")


def _move(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if src.is_file() and dest.is_file() and src.read_bytes() == dest.read_bytes():
            src.unlink()
            return
        raise FileExistsError(f"Refusing to overwrite existing package file: {dest}")
    shutil.move(str(src), dest)


def _remap(value: Path, moves: dict[Path, Path]) -> Path:
    for src, dest in moves.items():
        if value == src:
            return dest
        try:
            return dest / value.relative_to(src)
        except ValueError:
            continue
    return value


def package_profile(package: Path) -> str | None:
    """Profile key (see profiles.PROFILES) of the package in `package`, from
    its ica-package.json or, for older packages, from the files it contains.
    A folder holding only archive/ is judged by its newest archived issuance."""
    candidates = [package]
    archive = package / ARCHIVE
    if archive.is_dir():
        candidates += sorted((p for p in archive.iterdir() if p.is_dir()), reverse=True)
    for folder in candidates:
        manifest = folder / RECORDS / MANIFEST
        if manifest.is_file():
            try:
                return json.loads(manifest.read_text(encoding="utf-8"))["profile"]
            except (ValueError, KeyError):
                pass
        if (folder / DEPLOY / "opcua-trust").is_dir() or (folder / "opcua-trust").is_dir():
            return "opcua_client" if find_package_file(folder, "client-certificate.pem") else "opcua_server"
        for name, profile in _PROFILE_SIGNATURES:
            if find_package_file(folder, name):
                return profile
    return None


def find_package_file(package: Path, name: str) -> Path | None:
    """Locate `name` in a package in the current layout or the older flat one."""
    for candidate in (package / _folder_for(name) / name, package / name,
                      package / DEPLOY / name, package / TRUST / name, package / RECORDS / name):
        if candidate.is_file():
            return candidate
    return None


def organize_package(output: Path, result: dict[str, Path], *, title: str,
                     summary: list[str], deploy_note: str, trust_note: str,
                     details: str = "", deploy_copies: tuple[str, ...] = (),
                     manifest: dict | None = None) -> dict[str, Path]:
    """Sort loose files in `output` into deploy/, trust/, records/, copy the
    CA files named in `deploy_copies` into deploy/ (for targets that need a
    trust anchor themselves), update `result` in place, and write README.txt."""
    moves: dict[Path, Path] = {}
    for entry in sorted(output.iterdir()):
        if entry.name in _RESERVED:
            continue
        dest = output / _folder_for(entry.name) / entry.name
        _move(entry, dest)
        moves[entry] = dest
    for key, value in list(result.items()):
        if isinstance(value, Path):
            result[key] = _remap(value, moves)
    for name in deploy_copies:
        source = output / TRUST / name
        if source.is_file():
            shutil.copy2(source, output / DEPLOY / name)
    if manifest is not None:
        manifest_path = output / RECORDS / MANIFEST
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps({"format": 1, **manifest}, indent=2) + "\n",
                                 encoding="utf-8", newline="\n")
        result["manifest"] = manifest_path
    readme = output / README
    readme.write_text(_render_readme(output, title, summary, deploy_note, trust_note, details),
                      encoding="utf-8", newline="\n")
    result["readme"] = readme
    return result


def _render_readme(output: Path, title: str, summary: list[str], deploy_note: str,
                   trust_note: str, details: str) -> str:
    lines = [title, "=" * len(title), ""]
    lines += summary
    lines += [f"Packaged: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", "",
              "WHAT TO DO WITH THIS FOLDER", ""]
    for label, note in (
            ("deploy/", deploy_note + " It contains the private key: copy it only to the target, "
                        "over a secure channel, and do not email or share it."),
            ("trust/", trust_note),
            ("records/", "ICA's records for this issuance (CSR, extensions, validation report). "
                         "Keep them with the project; they are never deployed.")):
        lines.append(textwrap.fill(note, width=78, initial_indent=f"  {label:<10}",
                                   subsequent_indent=" " * 12, break_on_hyphens=False))
    if (output / ARCHIVE).is_dir():
        lines.append("  archive/  Earlier issuances, moved aside automatically on reissue.")
    lines += ["", "FILES"]
    for folder in (DEPLOY, TRUST, RECORDS):
        root = output / folder
        if not root.is_dir():
            continue
        lines += ["", f"{folder}/"]
        for entry in sorted(root.iterdir(), key=lambda p: (p.is_dir(), p.name)):
            label = entry.name + ("/" if entry.is_dir() else "")
            description = _describe(entry.name)
            lines.append(f"  {label:<32} {description}".rstrip())
    if details:
        lines += ["", details.rstrip()]
    return "\n".join(lines) + "\n"
