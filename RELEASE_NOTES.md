# Version 0.10.1

- Fixed the Linux executable being unable to run the system OpenSSL on
  distributions whose OpenSSL is newer than the build machine's (for example
  Fedora with OpenSSL 3.5). The error named `OPENSSL_3.x.0' "not found" and
  every certificate operation failed. The bundled libraries no longer leak into
  the openssl process. Windows builds were not affected. This affected all
  earlier Linux releases.

# Version 0.10.0

- Added HiveMQ as an MQTT Broker software option, with server-authenticated
  TLS or mutual TLS (`client-authentication-mode` REQUIRED).
- HiveMQ packages include a PKCS#12 keystore (broker key, certificate, and
  issuing CA) and, for mutual TLS, a Java-compatible PKCS#12 truststore (issuing
  and root CA as `trustedCertEntry` items; requires OpenSSL 3.2+ `-jdktrust`).
- `hivemq-config.xml` works as a complete container config or as a marked
  listener block merged by `install-hivemq-tls.sh`. The keystore password is
  never written to the package; HiveMQ reads it from
  `HIVEMQ_TLS_KEYSTORE_PASSWORD`.
- `install-hivemq-tls.sh` validates the keystores, requires typed
  confirmation, backs up config.xml, preserves other listeners and file
  ownership, refuses to overwrite a foreign listener on the same port, stores
  the password in a root-only systemd EnvironmentFile, verifies the served
  certificate after restart, and writes a rollback script. On failure it rolls
  back automatically.
- `verify-hivemq-tls.sh` checks the broker chain and SAN, confirms that a
  client without a certificate is rejected, and confirms that a supplied
  client certificate receives an MQTT CONNACK. It needs only OpenSSL.
- Reorganized every certificate package into `deploy/` (copy to the target),
  `trust/` (CA certificates, trust installers, verify scripts), and `records/`
  (CSR, extensions, report), with a generated `README.txt` that lists every
  file and what to do with it. It replaces `README-RAM-HTTPS.txt`,
  `installation-guide.txt`, and `OPC-UA-INSTALLATION.txt`. Reissue and SVM
  import still accept packages in the old flat layout.
- Crimson and RAM packages now go to `crimson/servers/<name>` and
  `ram/servers/<name>`, matching `svm/servers`, `mqtt/brokers|clients`, and
  `opcua/servers|clients`. New projects no longer create `devices/`. For
  existing projects, issuing a device that is still in `devices/<name>` moves
  its package (same profile only) to the new folder and archives it there. The
  Issue preview announces the move beforehand, and ICA refuses if both
  locations already hold a package.
- The Issue screen's "Issuance mode" (new issuance, reuse the existing private
  key, or rotate the key) is available for every profile, not only RAM and
  SVM, and now sits above the Issue button.
- Each package records its profile, identity, serial number, and expiry in
  `records/ica-package.json`. Older packages are recognized by their files.
- Removed the duplicate CA copies: trust installers now sit next to
  `root-ca.pem`/`intermediate-ca.pem` in `trust/` instead of a separate
  `trust-installers/` folder with `*.cert.pem` copies in every package.
- Mosquitto packaging now has a single implementation (`ica/mqtt_packaging.py`)
  with a guarded installer: backup and rollback script, `include_dir` and port
  conflict checks, refusal of encrypted broker keys (which Mosquitto cannot
  unlock under systemd), `--test-config` validation on Mosquitto 2.1+, and a
  check of the served certificate after restart. This replaces the previous
  `mosquitto -t` check, which Mosquitto does not support.
- Mosquitto now serves `broker-fullchain.pem`, so clients that hold only
  `root-ca.pem` can verify the broker through the issuing CA.
- Bash deployment scripts are always written with LF line endings, including
  on Windows builds (SVM, HiveMQ, and Mosquitto scripts).
- New projects no longer create unused `backups/` and `reports/` folders, and
  the intermediate CA's `intermediate-ca.ext` lives in `intermediate-ca/`
  instead of the project root.
- MQTT client/device certificates can now be issued with only a Client ID,
  with no DNS/IP SAN required.
- Fixed: a certificate request rejected for missing SANs no longer leaves a
  partial private key and CSR in the output folder.

# Version 0.9.3

- Added a native SixView Manager HTTPS Server profile with RSA 2048,
  `serverAuth`, HTTPS key usage, and explicit DNS/IP SAN handling.
- Added SVM-compatible `server.crt`, `server.key`, and `server.csr` artifacts,
  plus leaf, chain, and traditional RSA key files.
- Added SVM package validation for keys, CSR identity, SAN typing and
  deduplication, certificate constraints, CA chains, PEM ordering, and root
  exclusion.
- Added an SVM-specific installation guide with TCP 18081 context and safe
  discovery steps. The guide records the verified SVM 3.1.0 Podman paths
  `/opt/svm/ssl/server.crt` and `/opt/svm/ssl/server.key`, while requiring
  path and persistence verification for other releases and deployment models.
- Documented the reviewed installer's systemd Quadlet persistence model and
  individual read-only certificate/key mounts, avoiding changes that disappear
  when the SVM container is recreated.
- Added a guarded `deploy-svm-certificate.sh` package helper with preflight
  validation, typed confirmation, persistent Quadlet mounts, root-only backup,
  automatic failure rollback, and retrying post-restart certificate
  verification with actionable failure diagnostics.
- Extended IMPORT to load an existing ICA SVM package, auto-detect its standard
  leaf/key/chain/CSR files, and create a new validated deployment package with
  the deploy helper without reissuing or modifying the source identity.
- Added safe SVM reissuance with key reuse or rotation and timestamped archive
  preservation.
- Fixed Windows-generated Linux trust installers to use Unix LF line endings,
  allowing the packaged Bash scripts to run directly on Linux.

# Version 0.9.2

- Added an "Also export a PKCS#12 (.pfx) bundle" option to the Issue screen
  for OPC UA Server certificates, for applications such as Kepware/
  KEPServerEX that import a combined certificate + private key + CA chain
  bundle instead of separate PEM files. The .pfx uses its own required
  password, which may differ from the issued private key's own password.
- Fixed `OpenSSLEngine.export_pkcs12` (previously unused, untested code) to
  correctly support a source private key and destination .pfx protected by
  different passwords.

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
