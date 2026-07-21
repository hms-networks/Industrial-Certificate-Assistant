# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

import json
from inspect import signature
from pathlib import Path

from ica.openssl_engine import OpenSSLEngine, Subject, normalize_sans
from ica.project import Project


def test_normalize_sans():
    assert normalize_sans(["edge.local", "192.168.1.5", "EDGE.local"]) == ["DNS:edge.local", "IP:192.168.1.5"]


def test_ca_validity_defaults_and_order(tmp_path: Path):
    parameters = signature(OpenSSLEngine.create_pki).parameters
    assert parameters["root_days"].default == 5475
    assert parameters["intermediate_days"].default == 3650

    engine = OpenSSLEngine()
    try:
        engine.create_pki(
            tmp_path / "invalid-validity",
            Subject("Invalid Root", "Test"),
            Subject("Invalid Issuing CA", "Test"),
            "",
            root_days=365,
            intermediate_days=365,
        )
    except ValueError as exc:
        assert "root CA validity" in str(exc)
    else:
        raise AssertionError("Equal root and intermediate validity should be rejected")


def test_ecdsa_pki_profile_settings(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "ecdsa-pki"
    project = Project(str(workspace), "Edge Org", "Edge PKI", "local")
    project.pki_key_type = "ECDSA"
    project.pki_key_size_or_curve = "P-256"
    project.pki_digest = "SHA-384"
    project.pki_validity_days = 548
    project.save()

    engine.create_pki(
        workspace,
        Subject("Edge Root", "Edge Org"),
        Subject("Edge Issuing", "Edge Org"),
        "",
        key_type=project.pki_key_type,
        key_size_or_curve=project.pki_key_size_or_curve,
        digest=project.pki_digest,
        intermediate_days=project.pki_validity_days,
        root_days=1096,
    )

    result = engine.issue_server(
        workspace,
        project.device_folder("edge-a"),
        Subject("edge-a.local", "Edge Org"),
        ["edge-a.local", "192.168.10.15"],
        "",
        "",
        key_type=project.pki_key_type,
        key_size_or_curve=project.pki_key_size_or_curve,
        digest=project.pki_digest,
        days=project.pki_validity_days,
    )

    cert_text = engine.inspect_certificate(result["certificate"]).lower()
    assert "ecdsa-with-sha384" in cert_text
    assert "id-ecpublickey" in cert_text
    assert "prime256v1" in cert_text


def test_full_pki(tmp_path: Path):
    engine = OpenSSLEngine()
    password = "temporary-test-password"
    workspace = tmp_path / "pki"
    project = Project(str(workspace), "Test", "Test PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("Test Root CA", "Test"), Subject("Test Issuing CA", "Test"), password)
    result = engine.issue_server(workspace, project.device_folder("edge"), Subject("edge.local", "Test"), ["edge.local", "192.168.1.10"], password, "device-key-password")
    assert engine.verify_key_matches(result["certificate"], result["private_key"], "device-key-password")
    assert "edge.local" in engine.inspect_certificate(result["certificate"])
    assert "OK" in engine.verify_chain(result["certificate"], result["ca_chain"])
    assert result["fullchain"].read_text().count("BEGIN CERTIFICATE") == 2
    assert result["windows_install"].exists()
    assert result["linux_install"].exists()


def test_legacy_project_migration(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "legacy-pki"
    engine.create_pki(workspace, Subject("Legacy Root", "Legacy Org"), Subject("Legacy Issuing", "Legacy Org"), "legacy-password")
    files = Project.legacy_files(workspace)
    original = {name: path.read_bytes() for name, path in files.items()}
    assert Project.is_legacy_workspace(workspace)
    project = Project.migrate_legacy(workspace, "Legacy Org")
    assert project.manifest.exists()
    assert project.ca_key_encrypted is True
    assert not Project.is_legacy_workspace(workspace)
    assert all(path.read_bytes() == original[name] for name, path in files.items())


def test_unencrypted_pki_and_device(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "unencrypted-pki"
    project = Project(str(workspace), "Lab", "Lab PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("Lab Root", "Lab"), Subject("Lab Issuing", "Lab"), "")
    result = engine.issue_server(workspace, project.device_folder("lab-edge"), Subject("lab-edge.local", "Lab"), ["lab-edge.local", "192.168.1.20"], "", "")
    assert engine.verify_key_matches(result["certificate"], result["private_key"], "")
    assert "ENCRYPTED" not in (workspace / "root-ca/private/root-ca.key.pem").read_text()
    assert "ENCRYPTED" not in result["private_key"].read_text()


def test_load_project_backfills_new_pki_fields(tmp_path: Path):
    workspace = tmp_path / "manifest-v1"
    workspace.mkdir(parents=True, exist_ok=True)
    manifest = workspace / "ica-project.json"
    manifest.write_text(
        json.dumps(
            {
                "workspace": str(workspace),
                "organization": "Legacy Org",
                "project_name": "Legacy PKI",
                "dns_suffix": "local",
                "ca_key_encrypted": True,
                "created_utc": "2026-01-01T00:00:00+00:00",
                "version": 1,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    project = Project.load(workspace)
    assert project.version == 2
    assert project.pki_key_type == "RSA"
    assert project.pki_key_size_or_curve == "RSA 3072"
    assert project.pki_digest == "SHA-256"
    assert project.pki_validity_days == 825
