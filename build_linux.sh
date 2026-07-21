#!/usr/bin/env bash
# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
python3 -m pip install -r requirements.txt
python3 -m PyInstaller --noconfirm --clean --windowed --onefile \
  --name IndustrialCertificateAssistant app.py
