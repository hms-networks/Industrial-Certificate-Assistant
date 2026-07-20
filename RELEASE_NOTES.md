# Version 0.4.0

- Reworked the interface using the HMS/Ecatcher visual language requested for
  the customer-facing executable.
- Added a persistent left workflow rail for certificate import, company CSR,
  private PKI creation, and device-certificate issuance.
- Added dark teal section headers, light content panels, compact status and
  footer bars, clearer primary actions, and improved form spacing.
- Preserved the existing PKI engine, passwordless options, automatic folders,
  validation reports, full-chain creation, and trust installers.

# Version 0.3.0

- Added persistent PKI projects with non-secret metadata.
- Added automatic project and device folder creation.
- Added project-driven organization and DNS defaults.
- Added device-name/IP inputs that derive Common Name, SANs, and output path.
- Added automatic `fullchain.pem`, `ca-chain.pem`, and validation reports.
- Added complete packaging for imported customer certificates.
- Added Windows and Linux CA trust installation and removal scripts.
- Added password requirements for GUI-generated private keys.
- Added overwrite protection for CA, CSR, and device identity files.
- Added end-to-end lifecycle tests for generated and imported packages.
- Added guided migration of version 0.1 PKI folders. Existing keys and
  certificates are detected, preserved, and registered as a version 0.2
  project without manual JSON editing.

The application does not automatically change a Crimson device. Uploading the
generated `fullchain.pem` and `private-key.pem` remains an authenticated,
explicit device-administration step.

The application window now reads its version dynamically and uses the customer-
facing subtitle “Guided SSL/TLS Management for Crimson 3.2 Devices.”

Version 0.3.0 makes private-key encryption customer-selectable for CA, CSR, and
FlexEdge workflows. Encryption is the default; unencrypted creation requires an
explicit warning confirmation, with a typed `UNENCRYPTED` acknowledgement for
CA keys. New encrypted keys include confirmation, show/hide, and strong-password
generation controls.

Project metadata records only whether the CA key is encrypted, never the
password. The Issue screen uses this flag to explain whether the CA-password
field is required.
