# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path


def render_mosquitto_tls_config(mutual_tls: bool = False) -> str:
    lines = [
        "listener 8883",
        "",
        "cafile /etc/mosquitto/certs/ca-chain.pem",
        # The full chain lets clients that hold only root-ca.pem build the path
        # to the root through the issuing CA.
        "certfile /etc/mosquitto/certs/broker-fullchain.pem",
        "keyfile /etc/mosquitto/certs/broker-private-key.pem",
        "",
        "tls_version tlsv1.2",
        "allow_anonymous false",
    ]
    if mutual_tls:
        lines += ["require_certificate true", "use_identity_as_username true"]
    lines += [
        "",
        "log_type error",
        "log_type warning",
        "log_type notice",
        "log_type information",
        "connection_messages true",
        "",
        "# Note: Mosquitto/OpenSSL may negotiate TLS 1.3 when available.",
        "# This configuration sets TLS 1.2 as the minimum accepted version.",
    ]
    if not mutual_tls:
        lines += [
            "#",
            "# Without mutual TLS, allow_anonymous false means clients need an MQTT",
            "# username and password. Configure password_file in mosquitto.conf.",
        ]
    return "\n".join(lines) + "\n"


_INSTALL_SCRIPT = r'''#!/usr/bin/env bash
# Installs the ICA Mosquitto TLS listener. Run from the package's deploy/ folder.
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MAIN_CONF=${MOSQUITTO_CONF:-/etc/mosquitto/mosquitto.conf}
CONF_DIR=${MOSQUITTO_CONF_DIR:-/etc/mosquitto/conf.d}
CERTS_DIR=${MOSQUITTO_CERTS_DIR:-/etc/mosquitto/certs}
SERVICE=${MOSQUITTO_SERVICE:-mosquitto.service}
TLS_CONF_DEST="$CONF_DIR/industrial-mqtt-tls.conf"
BACKUP_ROOT=${MOSQUITTO_BACKUP_ROOT:-/var/backups/industrial-certificate-assistant}
FILES=(broker-fullchain.pem broker-private-key.pem ca-chain.pem)
CHANGED=0
BACKUP=""

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    if (( CHANGED )) && [[ -n "$BACKUP" && -x "$BACKUP/rollback.sh" ]]; then
        printf 'Restoring the previous Mosquitto configuration...\n' >&2
        CHANGED=0
        "$BACKUP/rollback.sh" || true
    fi
    exit 1
}

(( EUID == 0 )) || fail "Run this installer with sudo."
command -v mosquitto >/dev/null 2>&1 || fail "Mosquitto is not installed."
for command in openssl systemctl install sha256sum awk timeout; do
    command -v "$command" >/dev/null 2>&1 || fail "Required command not found: $command"
done
for f in "${FILES[@]}" mosquitto-tls.conf; do
    [[ -f "$HERE/$f" ]] || fail "Missing package file: $HERE/$f"
done
[[ -f "$MAIN_CONF" ]] || fail "Mosquitto configuration not found: $MAIN_CONF"
getent group mosquitto >/dev/null || fail "The mosquitto group does not exist."
if grep -qE 'ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED' "$HERE/broker-private-key.pem"; then
    fail "broker-private-key.pem is encrypted. Mosquitto cannot prompt for a key passphrase when started by systemd. Reissue the broker certificate without key encryption, and protect the file with permissions instead."
fi
if ! grep -Eq "^[[:space:]]*include_dir[[:space:]]+$CONF_DIR/?[[:space:]]*$" "$MAIN_CONF"; then
    fail "$MAIN_CONF does not contain 'include_dir $CONF_DIR', so the TLS fragment would be ignored. Add that line (Debian/Ubuntu ship it by default) and rerun."
fi
if grep -RqsE '^[[:space:]]*listener[[:space:]]+8883([[:space:]]|$)' "$MAIN_CONF" "$CONF_DIR" --exclude="$(basename -- "$TLS_CONF_DEST")"; then
    fail "Another Mosquitto listener on port 8883 already exists. Remove it and rerun."
fi

echo "This installer will:"
echo "  - Back up the existing ICA TLS fragment and certificates"
echo "  - Install the broker certificate chain, key, and CA chain into $CERTS_DIR"
echo "  - Install the TLS listener fragment as $TLS_CONF_DEST"
echo "  - Restart $SERVICE and confirm the certificate served on port 8883"
read -r -p "Type INSTALL to continue: " confirm
[[ "$confirm" == "INSTALL" ]] || fail "Cancelled; no files were changed."

BACKUP="$BACKUP_ROOT/mosquitto-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$BACKUP"
[[ -f "$TLS_CONF_DEST" ]] && cp -a "$TLS_CONF_DEST" "$BACKUP/"
for f in "${FILES[@]}"; do
    [[ -f "$CERTS_DIR/$f" ]] && cp -a "$CERTS_DIR/$f" "$BACKUP/"
done
{
    echo '#!/usr/bin/env bash'
    echo 'set -uo pipefail'
    echo "if [[ -f '$BACKUP/$(basename -- "$TLS_CONF_DEST")' ]]; then cp -a '$BACKUP/$(basename -- "$TLS_CONF_DEST")' '$TLS_CONF_DEST'; else rm -f '$TLS_CONF_DEST'; fi"
    for f in "${FILES[@]}"; do
        echo "if [[ -f '$BACKUP/$f' ]]; then cp -a '$BACKUP/$f' '$CERTS_DIR/$f'; else rm -f '$CERTS_DIR/$f'; fi"
    done
    echo "systemctl restart '$SERVICE'"
    echo "systemctl --no-pager --full status '$SERVICE' | sed -n '1,10p'"
} >"$BACKUP/rollback.sh"
chmod 0700 "$BACKUP/rollback.sh"

CHANGED=1
install -d -m 0750 -o root -g mosquitto "$CERTS_DIR"
install -m 0644 -o root -g mosquitto "$HERE/broker-fullchain.pem" "$CERTS_DIR/broker-fullchain.pem"
install -m 0644 -o root -g mosquitto "$HERE/ca-chain.pem" "$CERTS_DIR/ca-chain.pem"
install -m 0640 -o root -g mosquitto "$HERE/broker-private-key.pem" "$CERTS_DIR/broker-private-key.pem"
install -d -m 0755 "$CONF_DIR"
install -m 0644 -o root -g root "$HERE/mosquitto-tls.conf" "$TLS_CONF_DEST"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R /etc/mosquitto || true
fi

# Mosquitto 2.1+ can check a configuration without starting a broker.
if mosquitto -h 2>&1 | grep -q -- '--test-config'; then
    mosquitto -c "$MAIN_CONF" --test-config || fail "Mosquitto rejected the new configuration."
fi
systemctl restart "$SERVICE" || fail "$SERVICE failed to restart. Check: journalctl -u $SERVICE"

EXPECTED=$(openssl x509 -in "$HERE/broker-fullchain.pem" -outform DER | sha256sum | awk '{print $1}')
SERVED=""
for attempt in {1..20}; do
    if timeout 3 openssl s_client -connect 127.0.0.1:8883 -showcerts </dev/null 2>/dev/null >"$BACKUP/served.txt" \
            || openssl x509 -in "$BACKUP/served.txt" -noout >/dev/null 2>&1; then
        SERVED=$(openssl x509 -in "$BACKUP/served.txt" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
        [[ "$SERVED" == "$EXPECTED" ]] && break
    fi
    sleep 1
done
[[ "$SERVED" == "$EXPECTED" ]] || fail "Mosquitto is not presenting the deployed broker certificate on port 8883. Check: journalctl -u $SERVICE"
rm -f "$BACKUP/served.txt"
CHANGED=0

echo
echo "Mosquitto TLS installed and serving the new certificate on port 8883."
echo "Backup and rollback script: $BACKUP/rollback.sh"
echo "Next, from a client machine: trust/verify-mqtt-tls.sh <broker-host> 8883 [client-cert client-key]"
'''


_REMOVE_SCRIPT = r'''#!/usr/bin/env bash
# Removes the ICA Mosquitto TLS listener installed by install-mosquitto-tls.sh.
set -euo pipefail

CONF_DIR=${MOSQUITTO_CONF_DIR:-/etc/mosquitto/conf.d}
CERTS_DIR=${MOSQUITTO_CERTS_DIR:-/etc/mosquitto/certs}
SERVICE=${MOSQUITTO_SERVICE:-mosquitto.service}
TLS_CONF_DEST="$CONF_DIR/industrial-mqtt-tls.conf"

if (( EUID != 0 )); then
    echo "Run as root." >&2
    exit 1
fi

echo "This will remove ICA-managed Mosquitto TLS files:"
echo "  $TLS_CONF_DEST"
echo "  $CERTS_DIR/broker-fullchain.pem"
echo "  $CERTS_DIR/broker-private-key.pem"
echo "  $CERTS_DIR/ca-chain.pem"
echo "To return to a previous certificate instead, run its rollback.sh from"
echo "/var/backups/industrial-certificate-assistant/."
read -r -p "Type REMOVE to continue: " confirm
[[ "$confirm" == "REMOVE" ]] || { echo "Cancelled."; exit 1; }

rm -f "$TLS_CONF_DEST" "$CERTS_DIR/broker-fullchain.pem" "$CERTS_DIR/broker-private-key.pem" "$CERTS_DIR/ca-chain.pem"
systemctl restart "$SERVICE"
systemctl --no-pager --full status "$SERVICE" | sed -n '1,10p'
echo "Mosquitto TLS listener removed."
'''


_VERIFY_SCRIPT = r'''#!/usr/bin/env bash
# Verifies the Mosquitto TLS listener from a client machine.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <broker-host> [port] [client-cert] [client-key]" >&2
  exit 1
fi

HOST="$1"
PORT="${2:-8883}"
CLIENT_CERT="${3:-}"
CLIENT_KEY="${4:-}"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CAFILE="$HERE/root-ca.pem"

command -v openssl >/dev/null 2>&1 || { echo "openssl is required." >&2; exit 1; }
command -v mosquitto_pub >/dev/null 2>&1 || { echo "mosquitto_pub is required." >&2; exit 1; }
command -v mosquitto_sub >/dev/null 2>&1 || { echo "mosquitto_sub is required." >&2; exit 1; }

if command -v nc >/dev/null 2>&1; then
  nc -vz "$HOST" "$PORT"
elif command -v timeout >/dev/null 2>&1; then
  timeout 5 bash -c "</dev/tcp/$HOST/$PORT" || { echo "TCP connectivity failed" >&2; exit 1; }
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

SCLIENT_ARGS=( -connect "$HOST:$PORT" -servername "$HOST" -CAfile "$CAFILE" -verify_return_error -showcerts )
if [[ -n "$CLIENT_CERT" && -n "$CLIENT_KEY" ]]; then
  SCLIENT_ARGS+=( -cert "$CLIENT_CERT" -key "$CLIENT_KEY" )
fi

openssl s_client "${SCLIENT_ARGS[@]}" </dev/null >"$TMPDIR/sclient.txt" 2>&1 || true
cat "$TMPDIR/sclient.txt"

awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{print}' "$TMPDIR/sclient.txt" > "$TMPDIR/chain.pem"
csplit -s -f "$TMPDIR/cert-" "$TMPDIR/chain.pem" '/-----BEGIN CERTIFICATE-----/' '{*}' >/dev/null 2>&1 || true
count=$(grep -c "BEGIN CERTIFICATE" "$TMPDIR/chain.pem" || true)
echo "Presented certificate count: $count"

if [[ -f "$TMPDIR/cert-01" ]]; then
  openssl x509 -in "$TMPDIR/cert-01" -noout -subject -issuer -dates -ext subjectAltName -fingerprint -sha256
fi

topic="ica/verify/$(date +%s)"
mosquitto_sub -h "$HOST" -p "$PORT" --cafile "$CAFILE" -t "$topic" -C 1 -W 10 ${CLIENT_CERT:+--cert "$CLIENT_CERT"} ${CLIENT_KEY:+--key "$CLIENT_KEY"} >"$TMPDIR/sub.txt" &
sub_pid=$!
sleep 1
mosquitto_pub -h "$HOST" -p "$PORT" --cafile "$CAFILE" -t "$topic" -m "ica-verify" ${CLIENT_CERT:+--cert "$CLIENT_CERT"} ${CLIENT_KEY:+--key "$CLIENT_KEY"}
wait "$sub_pid"
cat "$TMPDIR/sub.txt"
'''


def create_mqtt_broker_bundle(destination: Path, mutual_tls: bool = False) -> dict[str, Path]:
    scripts = {
        "mosquitto_conf": destination / "mosquitto-tls.conf",
        "mosquitto_install": destination / "install-mosquitto-tls.sh",
        "mosquitto_remove": destination / "remove-mosquitto-tls.sh",
        "mosquitto_verify": destination / "verify-mqtt-tls.sh",
    }
    scripts["mosquitto_conf"].write_text(render_mosquitto_tls_config(mutual_tls), encoding="utf-8", newline="\n")
    scripts["mosquitto_install"].write_text(_INSTALL_SCRIPT, encoding="utf-8", newline="\n")
    scripts["mosquitto_remove"].write_text(_REMOVE_SCRIPT, encoding="utf-8", newline="\n")
    scripts["mosquitto_verify"].write_text(_VERIFY_SCRIPT, encoding="utf-8", newline="\n")
    scripts["mosquitto_install"].chmod(0o755)
    scripts["mosquitto_remove"].chmod(0o755)
    scripts["mosquitto_verify"].chmod(0o755)
    return scripts
