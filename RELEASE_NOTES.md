# Version 0.9.1

- Wrong-password OpenSSL failures (for example an incorrect CA password) now
  raise a plain "Incorrect password" message instead of showing raw OpenSSL
  crypto stack trace text in the error dialog. The full OpenSSL diagnostic is
  still written to the activity log for troubleshooting.
- Fixed an issuance-retry bug: a wrong CA password used to fail only after
  ICA had already generated a new device private key, CSR, and `.ext` file on
  disk, leaving partial output that blocked retrying with the correct
  password. The CA password is now verified against the project's CA key
  before any output is created.
- The "Issue a protocol certificate" screen now checks the typed CA password
  against the loaded project's CA key as you type (debounced) and shows a
  live "CA password verified" / "Incorrect CA password" indicator.

# Version 0.9.0

- Added an OPC UA Client profile, mirroring the OPC UA Server workflow with
  its own `opcua/clients` project folder, `clientAuth`-only EKU, ApplicationUri
  handling, DER exports, CRL packaging, and installation guide.

# Version 0.8.0

- Added the first-class Red Lion RAM HTTPS Server profile.
- Added explicit DNS and IPv4/IPv6 SAN handling for RAM devices without
  automatically appending `.local`.
- Added RAM-compatible deployment artifacts including `private-key-rsa.pem`,
  `ram-https.pem`, `lighttpd-gau.pem`, and `README-RAM-HTTPS.txt`.
- Added validation for RAM certificate/key matching, chain validity, SANs,
  server authentication EKU, HTTPS key usage, `CA:FALSE`, PEM ordering, and
  root certificate exclusion.
- Added safe certificate reissuance with existing-key reuse or new-key
  rotation across RAM, Crimson, MQTT, and OPC UA workflows.
- Added timestamped archival of previous device certificate packages and key
  material during reissuance.
- Added issuing-CA lifetime enforcement for leaf certificates.
- Added Windows trust-installer elevation checks before LocalMachine changes.
- Added project reopening support with last-workspace restoration after
  restarting ICA.
- Imported project metadata now repopulates the PKI form, including
  organization, workspace, CA encryption, key settings, digest, and validity.
- Added bundled OpenSSL configuration discovery when running outside the
  packaged runtime hook.

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
