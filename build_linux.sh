#!/usr/bin/env bash
# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

readonly APP_NAME="IndustrialCertificateAssistant"
readonly APP_VERSION="0.9.0"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

require_file() {
  if [[ ! -f "$1" ]]; then
    printf 'ERROR: Required file was not found: %s\n' "$1" >&2
    exit 1
  fi
}

require_file "app.py"
require_file "requirements.txt"
require_file "pyi_rth_openssl.py"
command -v python3 >/dev/null 2>&1 || {
  printf 'ERROR: python3 was not found in PATH.\n' >&2
  exit 1
}

python3 -m pip install --disable-pip-version-check -r requirements.txt
printf '%s' "$APP_VERSION" > VERSION.txt

rm -rf -- build dist
rm -f -- "${APP_NAME}.spec"

args=(
  -m PyInstaller
  --noconfirm
  --clean
  --onefile
  --windowed
  --name "$APP_NAME"
  --runtime-hook "pyi_rth_openssl.py"
  --add-data "VERSION.txt:."
)

if [[ -f HMS_banner.png ]]; then
  if ! python3 -c 'from PIL import Image' >/dev/null 2>&1; then
    printf 'Installing Pillow to resize the PyInstaller splash image...\n'
    python3 -m pip install --disable-pip-version-check 'Pillow>=10,<13'
  fi
  args+=(--splash HMS_banner.png --add-data "HMS_banner.png:.")
elif [[ -f HMS_Banner.png ]]; then
  if ! python3 -c 'from PIL import Image' >/dev/null 2>&1; then
    printf 'Installing Pillow to resize the PyInstaller splash image...\n'
    python3 -m pip install --disable-pip-version-check 'Pillow>=10,<13'
  fi
  args+=(--splash HMS_Banner.png --add-data "HMS_Banner.png:.")
fi

args+=(app.py)
python3 "${args[@]}"

if [[ ! -x "dist/$APP_NAME" ]]; then
  printf 'ERROR: Expected output was not created: dist/%s\n' "$APP_NAME" >&2
  exit 1
fi

printf 'Built dist/%s (version %s)\n' "$APP_NAME" "$APP_VERSION"