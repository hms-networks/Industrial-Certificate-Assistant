# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path


def render_mosquitto_tls_config(mutual_tls: bool = False) -> str:
    lines = [
        "listener 8883",
        "",
        "cafile /etc/mosquitto/certs/ca-chain.pem",
        "certfile /etc/mosquitto/certs/broker-certificate.pem",
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
    return "\n".join(lines) + "\n"


def _install_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

if ! command -v mosquitto >/dev/null 2>&1; then
  echo "Mosquitto is not installed." >&2
  exit 1
fi

HERE=\"$(cd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\" && pwd)\"
CERTS_DIR=\"/etc/mosquitto/certs\"
TLS_CONF_DEST=\"/etc/mosquitto/conf.d/industrial-mqtt-tls.conf\"
BACKUP_DIR=\"/etc/mosquitto/ica-backups\"
STAMP=\"$(date +%Y%m%d-%H%M%S)\"
BACKUP_CONF=\"$BACKUP_DIR/mosquitto.conf.$STAMP.bak\"
BACKUP_TLS=\"$BACKUP_DIR/industrial-mqtt-tls.conf.$STAMP.bak\"

FILES=(
  broker-certificate.pem
  broker-fullchain.pem
  ca-chain.pem
  root-ca.pem
  broker-private-key.pem
)

echo "This installer will:"
echo "  - Backup /etc/mosquitto/mosquitto.conf and existing industrial TLS fragment"
echo "  - Install broker certs into $CERTS_DIR"
echo "  - Install TLS fragment into $TLS_CONF_DEST"
echo "  - Validate config before restarting mosquitto"
read -r -p "Type INSTALL to continue: " confirm
[[ \"$confirm\" == "INSTALL" ]] || { echo "Cancelled."; exit 1; }

mkdir -p "$BACKUP_DIR"
if [[ -f /etc/mosquitto/mosquitto.conf ]]; then
  cp -a /etc/mosquitto/mosquitto.conf "$BACKUP_CONF"
fi
if [[ -f "$TLS_CONF_DEST" ]]; then
  cp -a "$TLS_CONF_DEST" "$BACKUP_TLS"
fi

install -d -m 0750 -o root -g mosquitto "$CERTS_DIR"

for f in "${FILES[@]}"; do
  src="$HERE/$f"
  [[ -f "$src" ]] || { echo "Missing required file: $src" >&2; exit 1; }
done

install -m 0644 -o root -g mosquitto "$HERE/broker-certificate.pem" "$CERTS_DIR/broker-certificate.pem"
install -m 0644 -o root -g mosquitto "$HERE/broker-fullchain.pem" "$CERTS_DIR/broker-fullchain.pem"
install -m 0644 -o root -g mosquitto "$HERE/ca-chain.pem" "$CERTS_DIR/ca-chain.pem"
install -m 0644 -o root -g mosquitto "$HERE/root-ca.pem" "$CERTS_DIR/root-ca.pem"
install -m 0640 -o root -g mosquitto "$HERE/broker-private-key.pem" "$CERTS_DIR/broker-private-key.pem"
install -m 0644 -o root -g root "$HERE/mosquitto-tls.conf" "$TLS_CONF_DEST"

if command -v restorecon >/dev/null 2>&1; then
  restorecon -Rv /etc/mosquitto || true
fi

if ! mosquitto -c /etc/mosquitto/mosquitto.conf -v -d; then
  echo "Mosquitto config validation failed; restoring backups." >&2
  [[ -f "$BACKUP_CONF" ]] && cp -a "$BACKUP_CONF" /etc/mosquitto/mosquitto.conf
  [[ -f "$BACKUP_TLS" ]] && cp -a "$BACKUP_TLS" "$TLS_CONF_DEST" || rm -f "$TLS_CONF_DEST"
  exit 1
fi

pkill -f "mosquitto -c /etc/mosquitto/mosquitto.conf -v -d" >/dev/null 2>&1 || true

systemctl restart mosquitto
systemctl --no-pager --full status mosquitto | sed -n '1,10p'

if command -v ss >/dev/null 2>&1; then
  ss -ltnp | grep ':8883' || { echo "Port 8883 is not listening." >&2; exit 1; }
fi

echo "Mosquitto TLS installed. Suggested checks:"
echo "  openssl s_client -connect <broker-host>:8883 -servername <broker-dns> -CAfile $CERTS_DIR/root-ca.pem"
echo "  mosquitto_pub -h <broker-host> -p 8883 --cafile $CERTS_DIR/root-ca.pem -t ica/test -m hello"
"""


def _remove_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

TLS_CONF_DEST=\"/etc/mosquitto/conf.d/industrial-mqtt-tls.conf\"
CERTS_DIR=\"/etc/mosquitto/certs\"
BACKUP_DIR=\"/etc/mosquitto/ica-backups\"

echo "This will remove ICA-managed Mosquitto TLS files:"
echo "  $TLS_CONF_DEST"
echo "  $CERTS_DIR/broker-certificate.pem"
echo "  $CERTS_DIR/broker-fullchain.pem"
echo "  $CERTS_DIR/ca-chain.pem"
echo "  $CERTS_DIR/root-ca.pem"
echo "  $CERTS_DIR/broker-private-key.pem"
read -r -p "Type REMOVE to continue: " confirm
[[ \"$confirm\" == "REMOVE" ]] || { echo "Cancelled."; exit 1; }

rm -f "$TLS_CONF_DEST"
rm -f "$CERTS_DIR/broker-certificate.pem" "$CERTS_DIR/broker-fullchain.pem" "$CERTS_DIR/ca-chain.pem" "$CERTS_DIR/root-ca.pem" "$CERTS_DIR/broker-private-key.pem"

latest_conf_backup="$(ls -1t "$BACKUP_DIR"/mosquitto.conf.*.bak 2>/dev/null | head -n 1 || true)"
if [[ -n "$latest_conf_backup" ]]; then
  cp -a "$latest_conf_backup" /etc/mosquitto/mosquitto.conf
fi

latest_tls_backup="$(ls -1t "$BACKUP_DIR"/industrial-mqtt-tls.conf.*.bak 2>/dev/null | head -n 1 || true)"
if [[ -n "$latest_tls_backup" ]]; then
  cp -a "$latest_tls_backup" "$TLS_CONF_DEST"
fi

mosquitto -c /etc/mosquitto/mosquitto.conf -v -d
pkill -f "mosquitto -c /etc/mosquitto/mosquitto.conf -v -d" >/dev/null 2>&1 || true

systemctl restart mosquitto
systemctl --no-pager --full status mosquitto | sed -n '1,10p'

echo "Mosquitto TLS rollback completed."
"""


def _verify_script() -> str:
    return """#!/usr/bin/env bash
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
"""


def create_mqtt_broker_bundle(destination: Path, mutual_tls: bool = False) -> dict[str, Path]:
    scripts = {
        "mosquitto_conf": destination / "mosquitto-tls.conf",
        "mosquitto_install": destination / "install-mosquitto-tls.sh",
        "mosquitto_remove": destination / "remove-mosquitto-tls.sh",
        "mosquitto_verify": destination / "verify-mqtt-tls.sh",
    }
    scripts["mosquitto_conf"].write_text(render_mosquitto_tls_config(mutual_tls), encoding="utf-8")
    scripts["mosquitto_install"].write_text(_install_script(), encoding="utf-8")
    scripts["mosquitto_remove"].write_text(_remove_script(), encoding="utf-8")
    scripts["mosquitto_verify"].write_text(_verify_script(), encoding="utf-8")
    scripts["mosquitto_install"].chmod(0o755)
    scripts["mosquitto_remove"].chmod(0o755)
    scripts["mosquitto_verify"].chmod(0o755)
    return scripts
