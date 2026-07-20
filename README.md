# Industrial Certificate Assistant

Cross-platform guided PKI utility for FlexEdge HTTPS certificates and future
industrial TLS profiles. Cryptographic operations are performed by OpenSSL;
the desktop interface is built with Python and PySide6.

## Version 0.4.0 milestone

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
build_windows.bat
```

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
├── trust-installers/
├── backups/
└── reports/
```

Passwords are never stored in `ica-project.json`.
