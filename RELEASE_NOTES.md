# Version 0.5.0

- Added protocol-aware certificate issuance while preserving existing
  Crimson 3.2 HTTPS issuance behavior.
- Added MQTT broker issuance with SAN validation, deduplication, and
  broker-specific output naming.
- Added MQTT client/device issuance with `clientAuth` EKU and client
  identity-oriented defaults.
- Added project structure support for `mqtt/brokers` and `mqtt/clients`.
- Added Mosquitto broker packaging artifacts:
  - `mosquitto-tls.conf`
  - `install-mosquitto-tls.sh`
  - `remove-mosquitto-tls.sh`
  - `verify-mqtt-tls.sh`
- Added richer certificate report output including protocol/role/profile
  metadata, KU/EKU, signature and key information, chain validation,
  encryption state, and generated file lists.
- Added tests for MQTT profiles, issuance paths, SAN handling,
  Mosquitto script content, encryption modes, and report hygiene.

# Version 0.4.1

- Licensed the project under Apache License 2.0 with HMS Networks as the
  copyright holder.
- Added project notice and OpenSSL third-party redistribution documentation.
- Added a Windows packaging safeguard that requires OpenSSL license, notice,
  version, and SHA-256 records whenever bundled binaries are detected.
- Added `prepare_windows_openssl.bat` to create a minimal, documented OpenSSL
  vendor bundle, update Git exclusions, validate the runtime, and optionally
  remove local caches and sample test keys.
- Increased new root CA validity to 15 years and new intermediate CA validity
  to 10 years.
- Added validation that prevents an intermediate CA from having a lifetime
  equal to or longer than its root CA.

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
