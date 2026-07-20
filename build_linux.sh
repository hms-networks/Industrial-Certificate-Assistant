#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install -r requirements.txt
python3 -m PyInstaller --noconfirm --clean --windowed --onefile \
  --name IndustrialCertificateAssistant app.py

