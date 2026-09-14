from __future__ import annotations

from pathlib import Path


DEPLOY_SCRIPT = r'''#!/usr/bin/env bash
set -Eeuo pipefail

CONTAINER=${SVM_CONTAINER:-svm_container}
SERVICE=${SVM_SERVICE:-sixview-manager.service}
QUADLET=${SVM_QUADLET:-/etc/containers/systemd/sixview-manager.container}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CERTIFICATE="$HERE/server.crt"
PRIVATE_KEY="$HERE/server.key"
BACKUP_ROOT=${SVM_BACKUP_ROOT:-/var/backups/industrial-certificate-assistant}
CHANGED=0
BACKUP=""

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    if (( CHANGED )) && [[ -n "$BACKUP" && -x "$BACKUP/rollback.sh" ]]; then
        printf 'Restoring the previous Quadlet...\n' >&2
        CHANGED=0
        "$BACKUP/rollback.sh" || true
    fi
    exit 1
}
require() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

if (( EUID != 0 )); then
    fail "Run this deployment script with sudo."
fi
for command in openssl podman systemctl awk install sha256sum timeout mktemp; do
    require "$command"
done
[[ -f "$CERTIFICATE" ]] || fail "Missing package file: $CERTIFICATE"
[[ -f "$PRIVATE_KEY" ]] || fail "Missing package file: $PRIVATE_KEY"
[[ -f "$QUADLET" ]] || fail "SVM Quadlet not found: $QUADLET"
podman container exists "$CONTAINER" || fail "SVM container not found: $CONTAINER"

if grep -qE 'ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED' "$PRIVATE_KEY"; then
    fail "Encrypted server.key compatibility is unverified for SVM 3.1.0. Repackage with an explicitly approved unencrypted deployment key."
fi
openssl x509 -in "$CERTIFICATE" -noout -subject -issuer -dates -ext subjectAltName
openssl pkey -in "$PRIVATE_KEY" -noout -check >/dev/null
CERTIFICATE_KEY_HASH=$(openssl x509 -in "$CERTIFICATE" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
PRIVATE_KEY_HASH=$(openssl pkey -in "$PRIVATE_KEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[[ "$CERTIFICATE_KEY_HASH" == "$PRIVATE_KEY_HASH" ]] || fail "server.crt and server.key do not match."

if [[ -z ${SVM_SSL_DIR:-} ]]; then
    CONFIG_SOURCE=$(awk '
        /^Volume=/ && /:\/svm\/config\/config\.json([:,]|$)/ {
            value=$0; sub(/^Volume=/, "", value); sub(/:.*/, "", value); print value; exit
        }
    ' "$QUADLET")
    [[ -n "$CONFIG_SOURCE" ]] || fail "Cannot derive svm_install from the config.json mount. Set SVM_SSL_DIR to an absolute host directory."
    SVM_SSL_DIR=$(dirname -- "$(dirname -- "$CONFIG_SOURCE")")/svm_ssl
fi
[[ "$SVM_SSL_DIR" = /* ]] || fail "SVM_SSL_DIR must be an absolute path."

printf '\nPersistent certificate directory: %s\n' "$SVM_SSL_DIR"
printf 'Quadlet: %s\nService: %s\nContainer: %s\n\n' "$QUADLET" "$SERVICE" "$CONTAINER"
read -r -p "Type DEPLOY to back up the current configuration, install this certificate, and restart SVM: " answer
[[ "$answer" == "DEPLOY" ]] || fail "Deployment cancelled; no files were changed."

BACKUP="$BACKUP_ROOT/svm-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$BACKUP"
install -m 0600 "$QUADLET" "$BACKUP/sixview-manager.container"
podman cp "$CONTAINER:/opt/svm/ssl/server.crt" "$BACKUP/server.crt"
podman cp "$CONTAINER:/opt/svm/ssl/server.key" "$BACKUP/server.key"
chmod 0600 "$BACKUP/server.crt" "$BACKUP/server.key"

cat >"$BACKUP/rollback.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then echo "Run with sudo." >&2; exit 1; fi
install -m 0644 "$BACKUP/sixview-manager.container" "$QUADLET"
systemctl daemon-reload
systemctl restart "$SERVICE"
systemctl --no-pager --full status "$SERVICE"
EOF
chmod 0700 "$BACKUP/rollback.sh"

rollback_on_error() {
    exit_code=$1
    line=$2
    command=$3
    trap - ERR
    printf '\nERROR: command failed at line %s: %s\n' "$line" "$command" >&2
    if (( CHANGED )); then
        printf '\nDeployment failed; restoring the previous Quadlet...\n' >&2
        "$BACKUP/rollback.sh" || true
    fi
    exit "$exit_code"
}
trap 'rollback_on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

install -d -o root -g root -m 0700 "$SVM_SSL_DIR"
install -o root -g root -m 0644 "$CERTIFICATE" "$SVM_SSL_DIR/server.crt"
install -o root -g root -m 0600 "$PRIVATE_KEY" "$SVM_SSL_DIR/server.key"

QUADLET_TEMP=$(mktemp "${QUADLET}.XXXXXX")
awk -v cert="Volume=$SVM_SSL_DIR/server.crt:/opt/svm/ssl/server.crt:ro,Z" \
    -v key="Volume=$SVM_SSL_DIR/server.key:/opt/svm/ssl/server.key:ro,Z" '
    /^\[Container\]$/ { in_container=1 }
    in_container && /^Volume=.*:\/opt\/svm\/ssl\/server\.(crt|key)([:,]|$)/ { next }
    in_container && /^\[/ && $0 != "[Container]" {
        print cert; print key; in_container=0
    }
    { print }
    END { if (in_container) { print cert; print key } }
' "$QUADLET" >"$QUADLET_TEMP"
install -m 0644 "$QUADLET_TEMP" "$QUADLET"
rm -f "$QUADLET_TEMP"
CHANGED=1

systemctl daemon-reload
systemctl restart "$SERVICE"
systemctl is-active --quiet "$SERVICE"

SERVED_CERTIFICATE=$(mktemp)
SERVED_ERROR=$(mktemp)
trap 'rm -f "$SERVED_CERTIFICATE" "$SERVED_ERROR"' EXIT
HTTPS_READY=0
for attempt in {1..30}; do
    if timeout 2 openssl s_client -connect 127.0.0.1:18081 -servername localhost -showcerts \
            </dev/null 2>"$SERVED_ERROR" >"$SERVED_CERTIFICATE" && \
            openssl x509 -in "$SERVED_CERTIFICATE" -noout >/dev/null 2>&1; then
        HTTPS_READY=1
        break
    fi
    sleep 1
done
if (( ! HTTPS_READY )); then
    printf 'Last TLS connection error:\n' >&2
    cat "$SERVED_ERROR" >&2
    systemctl --no-pager --full status "$SERVICE" >&2 || true
    fail "SVM did not present a parseable certificate on TCP 18081 within 30 seconds."
fi
EXPECTED_HASH=$(openssl x509 -in "$CERTIFICATE" -outform DER | sha256sum | awk '{print $1}')
SERVED_HASH=$(openssl x509 -in "$SERVED_CERTIFICATE" -outform DER | sha256sum | awk '{print $1}')
[[ "$EXPECTED_HASH" == "$SERVED_HASH" ]] || fail "SVM is not presenting the deployed leaf certificate."

CHANGED=0
trap - ERR
printf '\nSVM certificate deployment succeeded.\n'
openssl x509 -in "$SERVED_CERTIFICATE" -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName
printf '\nBackup and rollback script: %s\n' "$BACKUP/rollback.sh"
printf 'Retain this backup until SVM has been tested by DNS name and IP address.\n'
'''


def write_svm_deploy_script(output: Path) -> Path:
    path = output / "deploy-svm-certificate.sh"
    path.write_text(DEPLOY_SCRIPT, encoding="utf-8")
    path.chmod(0o755)
    return path
