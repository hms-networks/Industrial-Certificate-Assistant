# Industrial Certificate Assistant

Cross-platform guided PKI utility for FlexEdge HTTPS certificates and future
industrial TLS profiles. Cryptographic operations are performed by OpenSSL;
the desktop interface is built with Python and PySide6.

## Version 0.5.0 milestone

- Added protocol-aware issuance workflows for:
  - Crimson 3.2 HTTPS server certificates
  - MQTT broker certificates
  - MQTT client/device certificates
- Added MQTT broker packaging outputs with Mosquitto-ready TLS artifacts:
  - `mosquitto-tls.conf`
  - `install-mosquitto-tls.sh`
  - `remove-mosquitto-tls.sh`
  - `verify-mqtt-tls.sh`
- Added profile-aware issuance metadata and richer certificate validation
  reports, including EKU/KU, signature details, key details, SANs, chain
  validation, and generated file inventory.
- Added project folder support for `mqtt/brokers` and `mqtt/clients`.
- Added MQTT-focused unit tests for issuance, SAN validation/deduplication,
  script generation, and safety controls.

## Version 0.4.1 milestone

- Detect and report the OpenSSL installation.
- Create a remembered, non-secret PKI project (`ica-project.json`).
- Automatically create root, intermediate, device, request, backup, report,
  and trust-installer folders.
- Auto-fill organization, DNS suffix, common name, SANs, and device output
  location from the loaded project and device identity.
- Create a dedicated root CA and industrial-device intermediate CA.
- Issue a complete FlexEdge HTTPS package with DNS and IP SANs.
- Generate a private key and CSR for submission to a corporate CA.
- Inspect and verify customer-provided certificates and private keys.
- Export Crimson-compatible `certificate.pem`, `private-key.pem`,
  `fullchain.pem`, and `ca-chain.pem` files.
- Create a certificate validation report automatically.
- Generate interactive Windows PowerShell and Linux shell scripts for
  installing and removing the public CA trust certificates.
- Prevent accidental overwriting of existing CA and device private keys.
- Detect and migrate complete version 0.1 PKI workspaces through a guided
  confirmation dialog without changing existing keys or certificates.
- Allow customers to choose encrypted or unencrypted CA, CSR, and FlexEdge
  private keys. Encryption remains enabled by default.
- Provide password confirmation, show/hide, and strong-password generation
  controls for newly generated encrypted keys.
- Require explicit risk confirmation before creating unencrypted keys, with a
  typed confirmation for unencrypted CA private keys.
- Remember the non-secret CA encryption state in project metadata so the
  FlexEdge issuance screen indicates automatically whether a CA password is
  required.
- Store CA serial/index data in a user-selected workspace.
- Present the four certificate workflows in an HMS/Ecatcher-inspired light
  interface with a persistent navigation rail, teal section headers, compact
  status information, and clear primary actions.
- Default new root CAs to 15 years and intermediate issuing CAs to 10 years,
  while rejecting an intermediate validity that is not shorter than its root.
- Publish the project under the Apache License 2.0, copyright HMS Networks.
- Record OpenSSL third-party notices and prevent the Windows build from
  bundling OpenSSL without its license, notice, version, and checksum records.

VPN profiles are intentionally excluded because a separate VPN tool already
exists.

## Development

Python 3.11 or 3.12 and OpenSSL 3.x are recommended.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

## Packaging

PyInstaller must run separately on each target operating system. A Windows
build creates a Windows executable; a Linux build creates a Linux executable.

Windows:

```bat
prepare_windows_openssl.bat
build_windows.bat
```

`prepare_windows_openssl.bat` detects the locally staged OpenSSL release,
copies only its matching executable and runtime DLLs into the canonical vendor
folder, downloads the matching upstream license, creates notice/version/hash
records, updates `.gitignore`, untracks development artifacts, and validates
the portable runtime. It leaves the original development tree on disk unless
the user explicitly confirms removal of caches and sample PEM test keys.

Linux:

```bash
chmod +x build_linux.sh
./build_linux.sh
```

The Windows script automatically bundles `vendor/openssl/windows/openssl.exe`
when present. Add its required OpenSSL DLLs to the same directory. Only ship a
vetted OpenSSL distribution whose license and update process have been
reviewed. Linux uses the system OpenSSL installation by default.

## Important security behavior

- Private-key passwords are passed to OpenSSL using temporary, permission-
  restricted files, never command-line arguments.
- The activity log redacts password-file paths.
- Existing CA, CSR, and device files are never overwritten. The application
  asks the user to select a new project, request, or device name.
- CA, FlexEdge, and corporate-CA request private keys may be encrypted or
  unencrypted. Encryption is recommended and enabled by default; unencrypted
  creation requires an explicit risk acknowledgement.
- Trust-install scripts show the root certificate fingerprint and require the
  user to type `INSTALL`; they do not silently establish trust.
- The root CA is intended to remain offline. End-device certificates are
  issued by the intermediate CA.
- The corporate-CA CSR workflow is the preferred enterprise deployment path.

## Automated project layout

```text
Industrial_Certs/
├── ica-project.json
├── root-ca/
├── intermediate-ca/
├── pending-requests/
├── devices/
├── mqtt/
│   ├── brokers/
│   └── clients/
├── trust-installers/
├── backups/
└── reports/
```

Passwords are never stored in `ica-project.json`.

## License

Copyright 2026 HMS Networks. Licensed under the Apache License 2.0. See
`LICENSE` and `NOTICE`. OpenSSL redistribution information is documented in
`THIRD_PARTY_NOTICES.md`.
