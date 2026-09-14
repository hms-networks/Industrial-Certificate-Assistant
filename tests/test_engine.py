# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

import json
import re
import subprocess
from inspect import signature
from pathlib import Path

from app import IMPORT_PACKAGE_TITLES, ISSUE_PROFILE_TITLES
from ica.openssl_engine import OpenSSLEngine, OpenSSLError, Subject, normalize_application_uri, normalize_sans
from ica.profiles import PROFILES
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
    assert b"\r\n" not in result["linux_install"].read_bytes()
    assert b"\r\n" not in result["linux_remove"].read_bytes()


def test_issue_ram_https_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "ram-pki"
    project = Project(str(workspace), "GregNet", "RAM PKI", "local")
    project.save()
    engine.create_pki(
        workspace,
        Subject("GregNet Industrial Root CA", "GregNet"),
        Subject("GregNet Industrial Device Issuing CA", "GregNet"),
        "",
        root_days=5475,
        intermediate_days=3650,
    )

    result = engine.issue_ram_https(
        workspace,
        project.device_folder("RAMTEST01"),
        Subject("RAMTEST01", "GregNet"),
        ["192.168.1.10", "ramtest01.example.local", "2001:db8::10"],
        "",
        "",
        days=3500,
    )

    assert "2048 bit" in engine.inspect_certificate(result["certificate"])
    assert result["private_key_rsa"].read_text().startswith("-----BEGIN RSA PRIVATE KEY-----")
    deployment = result["ram_https"].read_bytes()
    assert deployment.count(b"BEGIN CERTIFICATE") == 2
    assert deployment.count(b"BEGIN RSA PRIVATE KEY") == 1
    assert deployment.find(b"BEGIN CERTIFICATE") < deployment.find(b"BEGIN RSA PRIVATE KEY")
    assert project.device_folder("RAMTEST01").joinpath("root-ca.pem").read_bytes() not in deployment
    assert result["readme_ram_https"].exists()


def test_issue_sixview_manager_https_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "svm-pki"
    project = Project(str(workspace), "GregNet", "SVM PKI", "local")
    project.save()
    engine.create_pki(
        workspace,
        Subject("GregNet Industrial Root CA", "GregNet"),
        Subject("GregNet Industrial Device Issuing CA", "GregNet"),
        "",
    )
    output = project.svm_server_folder("svm-test")
    result = engine.issue_sixview_manager_https(
        workspace, output, Subject("svm-test.gregnet.local", "GregNet"),
        ["svm-test.gregnet.local", "192.168.1.50", "svm-alt.gregnet.local",
         "192.168.1.51", "SVM-TEST.GREGNET.LOCAL"],
        "", "svm-key-password",
    )

    required = {
        "certificate.pem", "private-key.pem", "private-key-rsa.pem", "ca-chain.pem",
        "fullchain.pem", "server.crt", "server.key", "server.csr",
        "certificate-report.txt", "installation-guide.txt", "deploy-svm-certificate.sh",
    }
    assert required <= {path.name for path in output.iterdir()}
    certificate_text = engine.inspect_certificate(result["certificate"])
    subject_text = engine.run("x509", "-in", str(result["certificate"]), "-noout", "-subject")
    assert re.search(r"CN\s*=\s*svm-test\.gregnet\.local", subject_text)
    assert "DNS:svm-test.gregnet.local" in certificate_text
    assert "DNS:svm-alt.gregnet.local" in certificate_text
    assert "IP Address:192.168.1.50" in certificate_text
    assert "IP Address:192.168.1.51" in certificate_text
    assert certificate_text.count("DNS:svm-test.gregnet.local") == 1
    assert "TLS Web Server Authentication" in certificate_text
    assert "TLS Web Client Authentication" not in certificate_text
    assert "Digital Signature, Key Encipherment" in certificate_text
    assert "CA:FALSE" in certificate_text
    assert engine.verify_key_matches(result["certificate"], result["private_key"], "svm-key-password")
    assert engine.verify_key_matches(result["certificate"], result["server_key"], "svm-key-password")
    assert "ENCRYPTED" in result["private_key_rsa"].read_text(encoding="utf-8")
    assert result["server_certificate"].read_bytes() == result["fullchain"].read_bytes()
    assert result["server_certificate"].read_text().count("BEGIN CERTIFICATE") == 2
    assert result["root"].read_bytes() not in result["server_certificate"].read_bytes()
    assert "CSR / Certificate SAN Match: PASS" in result["report"].read_text(encoding="utf-8")
    guide = result["installation_guide"].read_text(encoding="utf-8")
    assert "TCP 18081" in guide
    assert "/opt/svm/ssl/server.crt" in guide
    assert "/opt/svm/ssl/server.key" in guide
    assert "SVM 3.1.0 container image only" in guide
    assert "may be lost when the container is recreated" in guide
    assert "single self-signed leaf certificate" in guide
    assert "Encrypted server.key compatibility is therefore unverified" in guide
    assert "ICA never weakens the key policy silently" in guide
    assert "/etc/containers/systemd/sixview-manager.container" in guide
    assert "server.crt:/opt/svm/ssl/server.crt:ro,Z" in guide
    assert "server.key:/opt/svm/ssl/server.key:ro,Z" in guide
    assert "Do not mount an empty directory over /opt/svm/ssl" in guide
    assert "use mode 0600" in guide
    assert "sudo grep -RniE" in guide
    deploy_script = result["deploy_script"]
    deploy_text = deploy_script.read_text(encoding="utf-8")
    assert deploy_script.stat().st_mode & 0o111
    assert "Type DEPLOY" in deploy_text
    assert "server.crt and server.key do not match" in deploy_text
    assert "Encrypted server.key compatibility is unverified" in deploy_text
    assert "podman cp" in deploy_text
    assert "Volume=$SVM_SSL_DIR/server.crt:/opt/svm/ssl/server.crt:ro,Z" in deploy_text
    assert "Volume=$SVM_SSL_DIR/server.key:/opt/svm/ssl/server.key:ro,Z" in deploy_text
    assert "rollback_on_error" in deploy_text
    assert "openssl s_client -connect 127.0.0.1:18081" in deploy_text
    assert "for attempt in {1..30}" in deploy_text
    assert "SVM did not present a parseable certificate on TCP 18081 within 30 seconds" in deploy_text
    assert "command failed at line" in deploy_text
    assert "2>/dev/null >\"$SERVED_CERTIFICATE\"" not in deploy_text
    assert "rm -f /opt/svm/ssl" not in deploy_text
    assert "root-ca.key.pem" not in deploy_text
    assert "intermediate-ca.key.pem" not in deploy_text
    subprocess.run(["bash", "-n", str(deploy_script)], check=True)

    try:
        engine.issue_sixview_manager_https(
            workspace, output, Subject("svm-test.gregnet.local", "GregNet"),
            ["svm-test.gregnet.local"], "", "svm-key-password", reissue="invalid",
        )
    except ValueError as exc:
        assert "Reissue mode" in str(exc)
    else:
        raise AssertionError("Existing SVM output must not be silently overwritten")


def test_sixview_manager_reissue_reuses_and_rotates_key(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "svm-reissue"
    project = Project(str(workspace), "GregNet", "SVM PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("GregNet Root", "GregNet"), Subject("GregNet Issuing", "GregNet"), "")
    output = project.svm_server_folder("svm-test")
    first = engine.issue_sixview_manager_https(
        workspace, output, Subject("svm-test.local", "GregNet"),
        ["svm-test.local", "10.0.0.1"], "", "",
    )
    first_key = first["private_key"].read_bytes()
    reused = engine.issue_sixview_manager_https(
        workspace, output, Subject("svm-test.local", "GregNet"),
        ["svm-test.local", "10.0.0.2"], "", "", reissue="existing",
    )
    assert reused["private_key"].read_bytes() == first_key
    assert reused["archive"].joinpath("server.crt").exists()

    rotated = engine.issue_sixview_manager_https(
        workspace, output, Subject("svm-test.local", "GregNet"),
        ["svm-test.local", "10.0.0.3"], "", "", reissue="new",
    )
    assert rotated["private_key"].read_bytes() != first_key
    assert rotated["archive"].joinpath("private-key.pem").exists()


def test_package_existing_sixview_manager_identity_without_reissue(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "existing-svm-pki"
    project = Project(str(workspace), "GregNet", "SVM PKI", "local")
    project.save()
    engine.create_pki(
        workspace, Subject("GregNet Root", "GregNet"),
        Subject("GregNet Issuing", "GregNet"), "")
    issued = engine.issue_sixview_manager_https(
        workspace, project.svm_server_folder("svm-source"),
        Subject("svm.example.local", "GregNet"),
        ["svm.example.local", "192.168.1.50"], "", "")
    source_files = (issued["certificate"], issued["private_key"], issued["ca_chain"], issued["csr"])
    source_bytes = {path: path.read_bytes() for path in source_files}
    source_serial = engine.run(
        "x509", "-in", str(issued["certificate"]), "-noout", "-serial")

    output = project.svm_server_folder("svm-imported")
    packaged = engine.package_existing_sixview_manager_https(
        issued["certificate"], issued["private_key"], issued["ca_chain"],
        output, csr=issued["csr"])

    assert all(path.read_bytes() == source_bytes[path] for path in source_files)
    assert engine.run("x509", "-in", str(packaged["certificate"]), "-noout", "-serial") == source_serial
    assert packaged["certificate"].read_bytes() == issued["certificate"].read_bytes()
    assert packaged["private_key"].read_bytes() == issued["private_key"].read_bytes()
    assert packaged["csr"].read_bytes() == issued["csr"].read_bytes()
    assert packaged["server_certificate"].read_text().count("BEGIN CERTIFICATE") == 2
    assert packaged["root"].read_bytes() not in packaged["server_certificate"].read_bytes()
    assert engine.verify_key_matches(packaged["server_certificate"], packaged["server_key"], "")
    assert packaged["deploy_script"].exists()
    assert packaged["deploy_script"].stat().st_mode & 0o111
    assert "no certificate issued" in packaged["report"].read_text(encoding="utf-8").lower()
    assert "did not issue" in packaged["installation_guide"].read_text(encoding="utf-8").lower()
    subprocess.run(["bash", "-n", str(packaged["deploy_script"])], check=True)

    try:
        engine.package_existing_sixview_manager_https(
            issued["server_certificate"], issued["private_key"], issued["ca_chain"],
            project.svm_server_folder("invalid-chain-input"))
    except ValueError as exc:
        assert "leaf-only certificate.pem" in str(exc)
    else:
        raise AssertionError("SVM import must reject a chain where a leaf input is required")


def test_ram_reissue_reuses_key_and_archives_previous_certificate(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "ram-reissue-pki"
    project = Project(str(workspace), "GregNet", "RAM PKI", "local")
    project.save()
    engine.create_pki(
        workspace,
        Subject("GregNet Root CA", "GregNet"),
        Subject("GregNet Issuing CA", "GregNet"),
        "",
        root_days=5475,
        intermediate_days=3650,
    )
    output = project.device_folder("RAMTEST01")
    first = engine.issue_ram_https(workspace, output, Subject("RAMTEST01", "GregNet"), ["192.168.1.10"], "", "", days=3500)
    old_key = first["private_key"].read_bytes()
    old_serial = re.search(r"Serial Number:\s*([0-9a-f:]+)", engine.inspect_certificate(first["certificate"]), re.IGNORECASE).group(1)

    second = engine.issue_ram_https(
        workspace, output, Subject("RAMTEST01", "GregNet"),
        ["192.168.1.10", "166.149.166.97"], "", "", days=3500, reissue="existing",
    )

    assert second["private_key"].read_bytes() == old_key
    assert "166.149.166.97" in engine.inspect_certificate(second["certificate"])
    assert old_serial != re.search(r"Serial Number:\s*([0-9a-f:]+)", engine.inspect_certificate(second["certificate"]), re.IGNORECASE).group(1)
    assert second["archive"].joinpath("certificate.pem").exists()
    assert engine.verify_key_matches(second["certificate"], second["private_key"], "")


def test_ram_reissue_with_new_key_archives_old_key(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "ram-new-key-pki"
    project = Project(str(workspace), "GregNet", "RAM PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("GregNet Root", "GregNet"), Subject("GregNet Issuing", "GregNet"), "", root_days=5475, intermediate_days=3650)
    output = project.device_folder("RAMTEST02")
    first = engine.issue_ram_https(workspace, output, Subject("RAMTEST02", "GregNet"), ["10.0.0.2"], "", "", days=3500)
    old_key = first["private_key"].read_bytes()
    second = engine.issue_ram_https(workspace, output, Subject("RAMTEST02", "GregNet"), ["10.0.0.3"], "", "", days=3500, reissue="new")
    assert second["private_key"].read_bytes() != old_key
    assert second["archive"].joinpath("private-key.pem").read_bytes() == old_key


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


def test_issue_requires_ca_password_for_encrypted_project(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "encrypted-pki"
    project = Project(str(workspace), "Lab", "Lab PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("Lab Root", "Lab"), Subject("Lab Issuing", "Lab"), "ca-password")

    try:
        engine.issue_server(
            workspace,
            project.device_folder("lab-edge"),
            Subject("lab-edge.local", "Lab"),
            ["lab-edge.local", "192.168.1.20"],
            "",
            "",
        )
    except ValueError as exc:
        assert "encrypted CA keys" in str(exc)
    else:
        raise AssertionError("Expected encrypted CA issuance without CA password to fail")


def test_issue_with_wrong_ca_password_gives_friendly_error(tmp_path: Path):
    log: list[str] = []
    engine = OpenSSLEngine(logger=log.append)
    workspace = tmp_path / "wrong-password-pki"
    project = Project(str(workspace), "Lab", "Lab PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("Lab Root", "Lab"), Subject("Lab Issuing", "Lab"), "ca-password")

    try:
        engine.issue_server(
            workspace,
            project.device_folder("lab-edge"),
            Subject("lab-edge.local", "Lab"),
            ["lab-edge.local", "192.168.1.20"],
            "definitely-the-wrong-password",
            "",
        )
    except OpenSSLError as exc:
        message = str(exc)
        assert "Incorrect password" in message
        assert "bad decrypt" not in message.lower()
        assert "pkcs12" not in message.lower()
    else:
        raise AssertionError("Expected issuance with an incorrect CA password to fail")

    assert any("error:" in entry.lower() for entry in log), (
        "Expected the raw OpenSSL diagnostic to still reach the activity log"
    )


def test_wrong_ca_password_leaves_no_partial_output_and_retry_succeeds(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "retry-after-wrong-password"
    project = Project(str(workspace), "Lab", "Lab PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("Lab Root", "Lab"), Subject("Lab Issuing", "Lab"), "ca-password")
    output = project.device_folder("lab-edge")

    try:
        engine.issue_server(
            workspace, output, Subject("lab-edge.local", "Lab"),
            ["lab-edge.local", "192.168.1.20"], "wrong-password", "",
        )
    except OpenSSLError:
        pass
    else:
        raise AssertionError("Expected issuance with an incorrect CA password to fail")

    assert not output.exists(), (
        "A wrong CA password must not leave a partially generated device key/CSR behind"
    )

    result = engine.issue_server(
        workspace, output, Subject("lab-edge.local", "Lab"),
        ["lab-edge.local", "192.168.1.20"], "ca-password", "",
    )
    assert result["certificate"].exists()


def test_package_existing_requires_password_for_encrypted_private_key(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "import-source"
    project = Project(str(workspace), "Lab", "Lab PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("Lab Root", "Lab"), Subject("Lab Issuing", "Lab"), "")
    issued = engine.issue_server(
        workspace,
        project.device_folder("lab-edge"),
        Subject("lab-edge.local", "Lab"),
        ["lab-edge.local", "192.168.1.20"],
        "",
        "device-password",
    )

    try:
        engine.package_existing(
            issued["certificate"],
            issued["private_key"],
            issued["ca_chain"],
            workspace / "imported-package",
            "",
        )
    except ValueError as exc:
        assert "encrypted" in str(exc).lower()
    else:
        raise AssertionError("Expected encrypted private key import without password to fail")


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
    assert project.pki_validity_days == 3650


def test_load_project_uses_selected_folder_after_cross_platform_move(tmp_path: Path):
    workspace = tmp_path / "moved-pki"
    project = Project(str(workspace), "Portable Org", "Portable PKI", "local")
    project.save()
    manifest_data = json.loads(project.manifest.read_text(encoding="utf-8"))
    manifest_data["workspace"] = r"C:\Users\operator\Desktop\Portable_PKI"
    project.manifest.write_text(json.dumps(manifest_data, indent=2) + "\n", encoding="utf-8")

    loaded = Project.load(workspace)

    assert loaded.path == workspace.resolve()
    assert loaded.manifest == workspace.resolve() / "ica-project.json"
    assert loaded.svm_server_folder("svm-test") == workspace.resolve() / "svm" / "servers" / "svm-test"
    assert json.loads(project.manifest.read_text(encoding="utf-8"))["workspace"].startswith("C:\\")


def test_mqtt_profiles_eku_constraints():
    broker = PROFILES["mqtt_broker"]
    client = PROFILES["mqtt_client"]
    assert "serverAuth" in broker.extended_key_usage
    assert "clientAuth" not in broker.extended_key_usage
    assert "clientAuth" in client.extended_key_usage
    assert "serverAuth" not in client.extended_key_usage


def test_sixview_manager_profile_and_project_folder(tmp_path: Path):
    profile = PROFILES["sixview_manager_https_server"]
    assert profile.title == "SixView Manager HTTPS Server"
    assert profile.leaf_key_type == "RSA"
    assert profile.extended_key_usage == ("serverAuth",)
    assert profile.key_usage == ("digitalSignature", "keyEncipherment")
    assert profile.title in ISSUE_PROFILE_TITLES
    assert "SixView Manager HTTPS Server package" in IMPORT_PACKAGE_TITLES

    project = Project(str(tmp_path / "svm-structure"), "SVM Org")
    project.save()
    assert (project.path / "svm" / "servers").is_dir()
    assert project.svm_server_folder("svm-test") == project.path / "svm" / "servers" / "svm-test"


def test_mqtt_project_folders_created(tmp_path: Path):
    workspace = tmp_path / "mqtt-structure"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    assert (workspace / "mqtt" / "brokers").is_dir()
    assert (workspace / "mqtt" / "clients").is_dir()


def test_issue_mqtt_broker_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "mqtt-broker"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("MQTT Root", "MQTT Org"), Subject("MQTT Issuing", "MQTT Org"), "")

    output = project.mqtt_broker_folder("broker-01")
    result = engine.issue_mqtt_broker(
        workspace,
        output,
        Subject("broker01.example.local", "MQTT Org"),
        ["broker01.example.local", "172.31.34.74", "broker01.example.local"],
        "",
        "broker-key-password",
        mutual_tls=True,
    )

    cert_text = engine.inspect_certificate(result["certificate"])
    assert "TLS Web Server Authentication" in cert_text
    assert "TLS Web Client Authentication" not in cert_text
    assert engine.verify_key_matches(result["certificate"], result["private_key"], "broker-key-password")
    assert "OK" in engine.verify_chain(result["certificate"], result["ca_chain"])
    assert result["fullchain"].read_text().count("BEGIN CERTIFICATE") == 2
    assert result["mosquitto_conf"].exists()
    assert result["mosquitto_install"].exists()
    assert result["mosquitto_remove"].exists()
    assert result["mosquitto_verify"].exists()
    assert "require_certificate true" in result["mosquitto_conf"].read_text(encoding="utf-8")
    assert "use_identity_as_username true" in result["mosquitto_conf"].read_text(encoding="utf-8")


def test_mqtt_broker_reissue_reuses_key_and_archives_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "mqtt-reissue"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("MQTT Root", "MQTT Org"), Subject("MQTT Issuing", "MQTT Org"), "")
    output = project.mqtt_broker_folder("broker-01")
    first = engine.issue_mqtt_broker(workspace, output, Subject("broker.local", "MQTT Org"), ["broker.local", "10.0.0.1"], "", "", days=3500)
    old_key = first["private_key"].read_bytes()
    second = engine.issue_mqtt_broker(workspace, output, Subject("broker.local", "MQTT Org"), ["broker.local", "10.0.0.2"], "", "", days=3500, reissue="existing")
    assert second["private_key"].read_bytes() == old_key
    assert second["archive"].joinpath("broker-private-key.pem").exists()
    assert "10.0.0.2" in engine.inspect_certificate(second["certificate"])


def test_opcua_reissue_reuses_key_and_archives_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "opcua-reissue"
    project = Project(str(workspace), "UA Org", "UA PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("UA Root", "UA Org"), Subject("UA Issuing", "UA Org"), "")
    output = project.opcua_server_folder("server-01")
    first = engine.issue_opcua_server(workspace, output, Subject("server.local", "UA Org"), ["server.local", "10.0.0.1"], "urn:server.local:server", "", "", days=3500)
    old_key = first["private_key"].read_bytes()
    second = engine.issue_opcua_server(workspace, output, Subject("server.local", "UA Org"), ["server.local", "10.0.0.2"], "urn:server.local:server", "", "", days=3500, reissue="existing")
    assert second["private_key"].read_bytes() == old_key
    assert second["archive"].joinpath("server-private-key.pem").exists()
    assert "10.0.0.2" in engine.inspect_certificate(second["certificate"])


def test_issue_mqtt_client_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "mqtt-client"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("MQTT Root", "MQTT Org"), Subject("MQTT Issuing", "MQTT Org"), "")

    output = project.mqtt_client_folder("client-01")
    result = engine.issue_mqtt_client(
        workspace,
        output,
        Subject("client-01", "MQTT Org"),
        ["client-01", "10.0.0.15"],
        "",
        "",
    )

    cert_text = engine.inspect_certificate(result["certificate"])
    assert "TLS Web Client Authentication" in cert_text
    assert "TLS Web Server Authentication" not in cert_text
    assert engine.verify_key_matches(result["certificate"], result["private_key"], "")
    assert "OK" in engine.verify_chain(result["certificate"], result["ca_chain"])
    assert result["fullchain"].read_text().count("BEGIN CERTIFICATE") == 2


def test_mqtt_san_dns_and_ip_and_dedup():
    sans = normalize_sans(["Broker.EXAMPLE.local", "172.31.34.74", "broker.example.local", "172.31.34.74"])
    assert sans == ["DNS:broker.example.local", "IP:172.31.34.74"]


def test_mqtt_invalid_ip_rejected():
    try:
        normalize_sans(["999.999.1.1"])
    except ValueError as exc:
        assert "Invalid DNS name or IP address" in str(exc)
    else:
        raise AssertionError("Invalid IP should be rejected")


def test_mosquitto_installer_safety_content(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "mqtt-scripts"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("MQTT Root", "MQTT Org"), Subject("MQTT Issuing", "MQTT Org"), "")
    result = engine.issue_mqtt_broker(
        workspace,
        project.mqtt_broker_folder("broker-safe"),
        Subject("broker-safe.local", "MQTT Org"),
        ["broker-safe.local", "10.0.0.1"],
        "",
        "",
        mutual_tls=False,
    )
    install_script = result["mosquitto_install"].read_text(encoding="utf-8")
    remove_script = result["mosquitto_remove"].read_text(encoding="utf-8")
    verify_script = result["mosquitto_verify"].read_text(encoding="utf-8")

    assert "root-ca.key.pem" not in install_script
    assert "intermediate-ca.key.pem" not in install_script
    assert "backup" in install_script.lower()
    assert "mosquitto -c /etc/mosquitto/mosquitto.conf" in install_script
    assert "restore" in install_script.lower()
    assert "Type REMOVE to continue" in remove_script
    assert "openssl s_client" in verify_script
    assert "mosquitto_pub" in verify_script
    assert "mosquitto_sub" in verify_script


def test_encrypted_and_passwordless_mqtt_private_keys(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "mqtt-encryption"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("MQTT Root", "MQTT Org"), Subject("MQTT Issuing", "MQTT Org"), "")

    encrypted = engine.issue_mqtt_broker(
        workspace,
        project.mqtt_broker_folder("enc-broker"),
        Subject("enc-broker.local", "MQTT Org"),
        ["enc-broker.local", "10.0.0.2"],
        "",
        "broker-pass",
    )
    assert "ENCRYPTED" in encrypted["private_key"].read_text()

    plain = engine.issue_mqtt_client(
        workspace,
        project.mqtt_client_folder("plain-client"),
        Subject("plain-client", "MQTT Org"),
        ["plain-client"],
        "",
        "",
    )
    assert "ENCRYPTED" not in plain["private_key"].read_text()


def test_report_and_manifest_do_not_contain_passwords(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "mqtt-report"
    project = Project(str(workspace), "MQTT Org", "MQTT PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("MQTT Root", "MQTT Org"), Subject("MQTT Issuing", "MQTT Org"), "")

    result = engine.issue_mqtt_broker(
        workspace,
        project.mqtt_broker_folder("report-broker"),
        Subject("report-broker.local", "MQTT Org"),
        ["report-broker.local", "10.0.0.3"],
        "",
        "s3cret-password",
    )

    report_text = result["report"].read_text(encoding="utf-8")
    manifest_text = project.manifest.read_text(encoding="utf-8")
    assert "s3cret-password" not in report_text
    assert "s3cret-password" not in manifest_text


def test_opcua_profile_and_application_uri_validation():
    profile = PROFILES["opcua_server"]
    assert profile.extended_key_usage == ("serverAuth", "clientAuth")
    assert profile.key_usage == ("digitalSignature", "keyEncipherment")
    assert normalize_application_uri("urn:red-0b-bd-84.local:server") == "urn:red-0b-bd-84.local:server"
    try:
        normalize_application_uri("https://red-0b-bd-84.local")
    except ValueError as exc:
        assert "Application URI" in str(exc)
    else:
        raise AssertionError("A non-URN OPC UA ApplicationUri should be rejected")


def test_issue_opcua_server_package_with_crl(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "opcua pki"
    project = Project(str(workspace), "AEP", "AEP OPC UA PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("AEP Root", "AEP"), Subject("AEP Issuing", "AEP"), "")

    result = engine.issue_opcua_server(
        workspace,
        project.opcua_server_folder("red-0b-bd-84"),
        Subject("red-0b-bd-84.local", "AEP"),
        ["red-0b-bd-84.local", "10.124.214.65"],
        "urn:red-0b-bd-84.local:server",
        "",
        "",
    )

    cert_text = engine.inspect_certificate(result["certificate"])
    assert "URI:urn:red-0b-bd-84.local:server" in cert_text
    assert "DNS:red-0b-bd-84.local" in cert_text
    assert "IP Address:10.124.214.65" in cert_text
    assert "TLS Web Server Authentication" in cert_text
    assert "TLS Web Client Authentication" in cert_text
    assert result["certificate_der"].read_bytes().startswith(b"0")
    assert result["crl_der"].read_bytes().startswith(b"0")
    assert result["root_der"].exists()
    assert result["intermediate_der"].exists()
    assert result["installation_guide"].exists()
    assert "OK" in engine.verify_chain(result["certificate"], result["ca_chain"])


def test_opcua_client_profile_extended_key_usage():
    profile = PROFILES["opcua_client"]
    assert profile.extended_key_usage == ("clientAuth",)
    assert profile.key_usage == ("digitalSignature", "keyEncipherment")


def test_issue_opcua_client_package_with_crl(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "opcua client pki"
    project = Project(str(workspace), "AEP", "AEP OPC UA PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("AEP Root", "AEP"), Subject("AEP Issuing", "AEP"), "")

    result = engine.issue_opcua_client(
        workspace,
        project.opcua_client_folder("uaexpert-01"),
        Subject("uaexpert-01.local", "AEP"),
        ["uaexpert-01.local", "10.124.214.66"],
        "urn:uaexpert-01.local:client",
        "",
        "",
    )

    cert_text = engine.inspect_certificate(result["certificate"])
    assert "URI:urn:uaexpert-01.local:client" in cert_text
    assert "DNS:uaexpert-01.local" in cert_text
    assert "IP Address:10.124.214.66" in cert_text
    assert "TLS Web Client Authentication" in cert_text
    assert "TLS Web Server Authentication" not in cert_text
    assert result["certificate_der"].read_bytes().startswith(b"0")
    assert result["crl_der"].read_bytes().startswith(b"0")
    assert result["root_der"].exists()
    assert result["intermediate_der"].exists()
    assert result["installation_guide"].exists()
    assert "OK" in engine.verify_chain(result["certificate"], result["ca_chain"])


def test_opcua_client_reissue_reuses_key_and_archives_package(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "opcua-client-reissue"
    project = Project(str(workspace), "UA Org", "UA PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("UA Root", "UA Org"), Subject("UA Issuing", "UA Org"), "")
    output = project.opcua_client_folder("client-01")
    first = engine.issue_opcua_client(workspace, output, Subject("client.local", "UA Org"), ["client.local", "10.0.0.1"], "urn:client.local:client", "", "", days=3500)
    old_key = first["private_key"].read_bytes()
    second = engine.issue_opcua_client(workspace, output, Subject("client.local", "UA Org"), ["client.local", "10.0.0.2"], "urn:client.local:client", "", "", days=3500, reissue="existing")
    assert second["private_key"].read_bytes() == old_key
    assert second["archive"].joinpath("client-private-key.pem").exists()
    assert "10.0.0.2" in engine.inspect_certificate(second["certificate"])


def test_export_pkcs12_for_opcua_server_with_unencrypted_key(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "opcua-pfx-unencrypted"
    project = Project(str(workspace), "AEP", "AEP OPC UA PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("AEP Root", "AEP"), Subject("AEP Issuing", "AEP"), "")
    result = engine.issue_opcua_server(
        workspace, project.opcua_server_folder("kepware"), Subject("kepware.local", "AEP"),
        ["kepware.local", "10.0.0.5"], "urn:kepware.local:server", "", "",
    )

    pfx = result["certificate"].with_suffix(".pfx")
    engine.export_pkcs12(result["certificate"], result["private_key"], result["ca_chain"], pfx, "pfx-pass")

    assert pfx.exists()
    engine.run("pkcs12", "-in", str(pfx), "-noout", "-passin", "file:{PASSFILE}", password="pfx-pass")
    try:
        engine.run("pkcs12", "-in", str(pfx), "-noout", "-passin", "file:{PASSFILE}", password="wrong-pfx-pass")
    except OpenSSLError:
        pass
    else:
        raise AssertionError("Expected opening the .pfx with the wrong password to fail")


def test_export_pkcs12_for_opcua_server_with_encrypted_key_and_different_pfx_password(tmp_path: Path):
    engine = OpenSSLEngine()
    workspace = tmp_path / "opcua-pfx-encrypted"
    project = Project(str(workspace), "AEP", "AEP OPC UA PKI", "local")
    project.save()
    engine.create_pki(workspace, Subject("AEP Root", "AEP"), Subject("AEP Issuing", "AEP"), "")
    result = engine.issue_opcua_server(
        workspace, project.opcua_server_folder("kepware-enc"), Subject("kepware-enc.local", "AEP"),
        ["kepware-enc.local", "10.0.0.6"], "urn:kepware-enc.local:server", "", "device-key-password",
    )
    assert "ENCRYPTED" in result["private_key"].read_text()

    pfx = result["certificate"].with_suffix(".pfx")
    engine.export_pkcs12(
        result["certificate"], result["private_key"], result["ca_chain"], pfx,
        pfx_password="pfx-only-password", key_password="device-key-password",
    )

    assert pfx.exists()
    engine.run("pkcs12", "-in", str(pfx), "-noout", "-passin", "file:{PASSFILE}", password="pfx-only-password")


def test_opcua_project_folder_created(tmp_path: Path):
    project = Project(str(tmp_path / "opcua-structure"), "AEP")
    project.save()
    assert (project.path / "opcua" / "servers").is_dir()
    assert (project.path / "opcua" / "clients").is_dir()