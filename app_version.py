"""Single runtime accessor for the version bundled by the build scripts."""

from __future__ import annotations

from pathlib import Path


FALLBACK_VERSION = "0.7.0"


def get_app_version() -> str:
    version_file = Path(__file__).resolve().with_name("VERSION.txt")
    try:
        value = version_file.read_text(encoding="ascii").strip()
    except OSError:
        return FALLBACK_VERSION
    return value or FALLBACK_VERSION


APP_VERSION = get_app_version()