# MQTT TLS Test Plan

## Purpose
Validate end-to-end MQTT TLS certificate generation and broker packaging in Industrial Certificate Assistant v0.5.0, without weakening PKI security controls.

## Test Topology
- Broker host: placeholder (test environment specific)
- Broker software: Mosquitto 2.x
- Client hosts: placeholder
- Certificate authority: ICA-generated private PKI

## Prerequisites
- Industrial Certificate Assistant v0.5.0 build
- OpenSSL available
- Mosquitto installed on target Linux host
- `mosquitto_pub` and `mosquitto_sub` installed for runtime checks
- Administrative access to target broker host

## Broker Identity Planning
- Define canonical broker DNS name used by clients.
- Define required IP SANs for direct-IP clients.
- Avoid unstable public IP identities when possible.
- Prefer stable DNS or fixed/elastic public addressing.

## Server-Authenticated TLS Procedure
1. Create/load a PKI project.
2. Issue MQTT broker certificate from the ISSUE workflow.
3. Include all required DNS/IP SAN entries.
4. Export broker package artifacts.
5. Transfer package to broker host.
6. Run `install-mosquitto-tls.sh` as root.
7. Validate listener and certificate presentation on port 8883.

## Mutual-TLS Procedure
1. Enable mutual TLS in the MQTT broker issuance form.
2. Reissue broker package and reinstall TLS configuration.
3. Issue MQTT client/device certificate.
4. Verify broker connection succeeds with client cert/key and fails without client cert/key.

## Crimson Configuration Placeholders
- Placeholder: Crimson MQTT broker endpoint host setting.
- Placeholder: Crimson MQTT broker endpoint port setting.
- Placeholder: Crimson TLS trust anchor import/config steps.
- Placeholder: Crimson client certificate/key upload steps if mutual TLS is enabled.

## OpenSSL Verification
- Validate remote certificate chain and hostname/SANs:

```bash
openssl s_client -connect <broker-host>:8883 -servername <broker-dns> -CAfile root-ca.pem -showcerts
```

## Mosquitto Publish/Subscribe Verification
- Basic broker verification:

```bash
mosquitto_sub -h <broker-host> -p 8883 --cafile root-ca.pem -t ica/test -C 1 -W 10 &
mosquitto_pub -h <broker-host> -p 8883 --cafile root-ca.pem -t ica/test -m hello
```

- Mutual TLS verification:

```bash
mosquitto_sub -h <broker-host> -p 8883 --cafile root-ca.pem --cert client-certificate.pem --key client-private-key.pem -t ica/test -C 1 -W 10 &
mosquitto_pub -h <broker-host> -p 8883 --cafile root-ca.pem --cert client-certificate.pem --key client-private-key.pem -t ica/test -m hello-mtls
```

## Positive and Negative Tests
- Positive:
  - Broker cert with valid DNS SAN connects successfully.
  - Broker cert with valid IP SAN connects successfully.
  - MQTT client cert authenticates successfully when mutual TLS is enabled.
- Negative:
  - Hostname mismatch fails verification.
  - Missing CA trust fails verification.
  - Expired or untrusted certificate fails verification.
  - Mutual TLS connection without client cert fails when `require_certificate true` is set.

## Screenshot Checklist
- ISSUE workflow with MQTT Broker selected
- ISSUE workflow with MQTT Client/Device selected
- Generated broker output folder
- Generated client output folder
- `mosquitto-tls.conf` content
- Installer confirmation prompt
- Successful TLS listener check on port 8883
- OpenSSL `s_client` output showing subject/issuer/SAN
- Successful and failed mutual TLS attempts

## Completion Checklist
- [ ] Existing HTTPS workflow still passes regression tests.
- [ ] MQTT broker issuance creates expected files.
- [ ] MQTT client issuance creates expected files.
- [ ] EKU values match selected MQTT roles.
- [ ] Broker full chain excludes root certificate.
- [ ] CA chain includes intermediate then root.
- [ ] Installer does not copy CA private keys.
- [ ] Removal script restores broker config safely.
- [ ] Verification script reports useful failures.

## Troubleshooting
| Symptom | Probable Cause | Check | Fix |
| --- | --- | --- | --- |
| TLS handshake fails | SAN mismatch | Compare client endpoint vs cert SANs | Reissue with correct SANs |
| Broker fails to restart | Invalid mosquitto config | `mosquitto -c /etc/mosquitto/mosquitto.conf -v` | Restore backup, fix fragment |
| Client rejected in mTLS mode | Missing client cert or wrong CA | Broker logs and verify client chain | Reissue client cert and trust chain |
| Chain validation fails | Wrong CA file order | Inspect `ca-chain.pem` ordering | Rebuild chain as intermediate then root |
| Connection intermittently fails by public IP | Address changed | DNS/IP mapping checks | Use stable DNS/Elastic IP |
