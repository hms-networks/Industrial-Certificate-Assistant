"""Configure bundled OpenSSL before the packaged application starts."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _bundle_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def _configure_bundled_openssl() -> None:
    root = _bundle_root()
    openssl_dir = root / "vendor" / "openssl" / "windows"
    openssl_exe = openssl_dir / "openssl.exe"

    if not openssl_exe.is_file():
        return

    config_candidates = (
        openssl_dir / "openssl.cnf",
        openssl_dir / "cnf" / "openssl.cnf",
    )
    openssl_conf = next((path for path in config_candidates if path.is_file()), None)
    if openssl_conf is None:
        raise RuntimeError(f"Bundled OpenSSL configuration was not found beneath {openssl_dir}")

    os.environ["OPENSSL_CONF"] = str(openssl_conf)
    os.environ["PATH"] = f"{openssl_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    module_candidates = (
        openssl_dir / "ossl-modules",
        openssl_dir / "lib" / "ossl-modules",
    )
    modules_dir = next((path for path in module_candidates if path.is_dir()), None)
    if modules_dir is not None:
        os.environ["OPENSSL_MODULES"] = str(modules_dir)


_configure_bundled_openssl()