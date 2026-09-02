# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


MANIFEST_NAME = "ica-project.json"


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    if not value:
        raise ValueError("A device or project name is required.")
    return value


@dataclass
class Project:
    workspace: str
    organization: str
    project_name: str = "Industrial PKI"
    dns_suffix: str = "local"
    ca_key_encrypted: bool | None = None
    pki_key_type: str = "RSA"
    pki_key_size_or_curve: str = "RSA 3072"
    pki_digest: str = "SHA-256"
    pki_validity_days: int = 3650
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: int = 2

    @property
    def path(self) -> Path:
        return Path(self.workspace)

    @property
    def manifest(self) -> Path:
        return self.path / MANIFEST_NAME

    def create_structure(self) -> None:
        for relative in (
            "root-ca/certs", "root-ca/private", "intermediate-ca/certs",
            "intermediate-ca/private", "devices", "pending-requests",
            "trust-installers", "backups", "reports", "mqtt/brokers",
            "mqtt/clients", "opcua/servers", "opcua/clients",
        ):
            (self.path / relative).mkdir(parents=True, exist_ok=True)

    def save(self) -> None:
        self.create_structure()
        self.manifest.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, workspace: str | Path) -> "Project":
        path = Path(workspace) / MANIFEST_NAME
        if not path.exists():
            raise FileNotFoundError(f"This is not an Industrial Certificate Assistant project: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = 2
        return cls(**data)

    def device_folder(self, device_name: str) -> Path:
        return self.path / "devices" / safe_name(device_name)

    def pending_folder(self, request_name: str) -> Path:
        return self.path / "pending-requests" / safe_name(request_name)

    def mqtt_broker_folder(self, name: str) -> Path:
        return self.path / "mqtt" / "brokers" / safe_name(name)

    def mqtt_client_folder(self, name: str) -> Path:
        return self.path / "mqtt" / "clients" / safe_name(name)

    def opcua_server_folder(self, name: str) -> Path:
        return self.path / "opcua" / "servers" / safe_name(name)

    def opcua_client_folder(self, name: str) -> Path:
        return self.path / "opcua" / "clients" / safe_name(name)

    @staticmethod
    def legacy_files(workspace: str | Path) -> dict[str, Path]:
        path = Path(workspace)
        return {
            "root_key": path / "root-ca" / "private" / "root-ca.key.pem",
            "root_certificate": path / "root-ca" / "certs" / "root-ca.cert.pem",
            "intermediate_key": path / "intermediate-ca" / "private" / "intermediate-ca.key.pem",
            "intermediate_certificate": path / "intermediate-ca" / "certs" / "intermediate-ca.cert.pem",
        }

    @classmethod
    def is_legacy_workspace(cls, workspace: str | Path) -> bool:
        path = Path(workspace)
        return not (path / MANIFEST_NAME).exists() and all(p.is_file() for p in cls.legacy_files(path).values())

    @classmethod
    def migrate_legacy(cls, workspace: str | Path, organization: str,
                       project_name: str | None = None, dns_suffix: str = "local") -> "Project":
        path = Path(workspace)
        if not cls.is_legacy_workspace(path):
            raise ValueError("The selected folder is not a complete legacy PKI workspace.")
        root_key = cls.legacy_files(path)["root_key"].read_bytes()
        project = cls(str(path), organization.strip(), project_name or path.name, dns_suffix,
                      ca_key_encrypted=b"ENCRYPTED" in root_key)
        if not project.organization:
            raise ValueError("Organization is required to migrate the project.")
        project.save()
        return project
