# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .profiles import CertificateProfile, PROFILES
from .trust_scripts import create_trust_bundle


class OpenSSLError(RuntimeError):
    pass


_PASSWORD_ERROR_SIGNATURES = ("bad decrypt", "bad password read", "maybe wrong password")


def _looks_like_wrong_password(output: str) -> bool:
    lowered = output.lower()
    return any(signature in lowered for signature in _PASSWORD_ERROR_SIGNATURES)


def is_encrypted_private_key(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return "ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text


@dataclass(frozen=True)
class Subject:
    common_name: str
    organization: str = ""
    organizational_unit: str = ""
    country: str = ""
    state: str = ""
    locality: str = ""

    def openssl_subject(self) -> str:
        values = (
            ("C", self.country), ("ST", self.state), ("L", self.locality),
            ("O", self.organization), ("OU", self.organizational_unit),
            ("CN", self.common_name),
        )
        return "/" + "/".join(f"{k}={_escape_subject(v)}" for k, v in values if v)


def _escape_subject(value: str) -> str:
    return value.replace("\\", "\\\\").replace("/", "\\/")


def normalize_sans(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip()
        if not value:
            continue
        try:
            normalized = f"IP:{ipaddress.ip_address(value)}"
        except ValueError:
            if re.fullmatch(r"[0-9.]+", value):
                raise ValueError(f"Invalid DNS name or IP address: {value}")
            if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
                raise ValueError(f"Invalid DNS name or IP address: {value}")
            normalized = f"DNS:{value.lower()}"
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


def normalize_application_uri(value: str) -> str:
    uri = value.strip()
    if not uri or not re.fullmatch(r"urn:[A-Za-z0-9][A-Za-z0-9._:-]{2,252}", uri):
        raise ValueError("OPC UA Application URI must be a valid urn: value, for example urn:device.local:server.")
    return uri


def _digest_name(value: str) -> str:
    digest = value.lower().replace("-", "")
    if digest not in {"sha256", "sha384", "sha512"}:
        raise ValueError(f"Unsupported digest: {value}")
    return digest


def _keygen_args(key_type: str, key_size_or_curve: str) -> list[str]:
    if key_type.upper() == "RSA":
        match = re.fullmatch(r"(?:RSA )?(2048|3072|4096)", key_size_or_curve)
        if not match:
            raise ValueError(f"Unsupported RSA key size: {key_size_or_curve}")
        return ["genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{match.group(1)}"]
    curves = {"P-256": "prime256v1", "P-384": "secp384r1"}
    if key_size_or_curve not in curves:
        raise ValueError(f"Unsupported ECDSA curve: {key_size_or_curve}")
    return ["genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curves[key_size_or_curve]}"]


def split_pem_certificates(data: bytes) -> list[bytes]:
    pattern = re.compile(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", re.DOTALL)
    certificates = [match.group(0) for match in pattern.finditer(data)]
    if not certificates:
        raise ValueError("The CA chain does not contain a PEM-encoded certificate.")
    return certificates


class OpenSSLEngine:
    def __init__(self, executable: str | Path | None = None, logger: Callable[[str], None] | None = None):
        self.executable = str(executable or self.find_executable())
        self.logger = logger or (lambda _: None)
        executable_path = Path(self.executable)
        config = executable_path.with_name("openssl.cnf")
        if config.is_file():
            os.environ.setdefault("OPENSSL_CONF", str(config))

    @staticmethod
    def find_executable() -> Path:
        bundled = Path(__file__).resolve().parent.parent / "vendor" / "openssl" / "windows" / "openssl.exe"
        if os.name == "nt" and bundled.exists():
            return bundled
        located = shutil.which("openssl")
        if not located:
            raise OpenSSLError("OpenSSL was not found. Install OpenSSL 3.x or add it to the application bundle.")
        return Path(located)

    def run(self, *args: str, password: str | None = None, cwd: Path | None = None) -> str:
        passwords = {"{PASSFILE}": password} if password is not None else {}
        return self._run(*args, passwords=passwords, cwd=cwd)

    def _run(self, *args: str, passwords: dict[str, str], cwd: Path | None = None) -> str:
        """Like `run`, but supports more than one distinct password placeholder
        in a single invocation (for example a PKCS#12 export's separate
        -passin/-passout values). Each dict key is a placeholder token that gets
        substituted with the path to its own temporary password file."""
        password_paths: list[Path] = []
        command = [self.executable, *args]
        try:
            for placeholder, value in passwords.items():
                fd, raw_path = tempfile.mkstemp(prefix="ica-pass-")
                password_path = Path(raw_path)
                os.write(fd, value.encode("utf-8"))
                os.close(fd)
                if os.name != "nt":
                    password_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                password_paths.append(password_path)
                command = [item.replace(placeholder, str(password_path)) for item in command]
            display = " ".join(command)
            for password_path in password_paths:
                display = display.replace(str(password_path), "<password-file>")
            self.logger(f"> {display}")
            proc = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
            output = (proc.stdout + proc.stderr).strip()
            if proc.returncode:
                if passwords and _looks_like_wrong_password(output):
                    self.logger(output)
                    raise OpenSSLError(
                        "Incorrect password: OpenSSL could not decrypt the private key with "
                        "the password you entered. Verify the password and try again. The "
                        "full OpenSSL error was written to the activity log."
                    )
                raise OpenSSLError(output or f"OpenSSL exited with status {proc.returncode}")
            if output:
                self.logger(output)
            return output
        finally:
            for password_path in password_paths:
                password_path.unlink(missing_ok=True)

    def version(self) -> str:
        return self.run("version").strip()

    def inspect_certificate(self, certificate: Path) -> str:
        # OpenSSL accepts repeated -ext arguments but prints only the last one
        # on some 3.0 builds. The complete text form is consistent across the
        # supported Windows and Linux versions and includes every extension.
        return self.run("x509", "-in", str(certificate), "-noout", "-text", "-fingerprint", "-sha256")

    def verify_key_matches(self, certificate: Path, private_key: Path, password: str = "") -> bool:
        cert_pub = self.run("x509", "-in", str(certificate), "-pubkey", "-noout")
        key_args = ["pkey", "-in", str(private_key), "-pubout"]
        if password:
            key_args.extend(["-passin", "file:{PASSFILE}"])
        key_pub = self.run(*key_args, password=password if password else None)
        return re.sub(r"\s+", "", cert_pub) == re.sub(r"\s+", "", key_pub)

    def verify_chain(self, certificate: Path, ca_file: Path) -> str:
        return self.run("verify", "-CAfile", str(ca_file), str(certificate))

    def certificate_not_after(self, certificate: Path) -> datetime:
        output = self.run("x509", "-in", str(certificate), "-noout", "-enddate")
        value = output.split("=", 1)[-1].strip()
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    def validate_server_certificate(self, certificate: Path, private_key: Path,
                                    ca_chain: Path, requested_sans: Iterable[str],
                                    key_password: str = "") -> list[str]:
        checks: list[str] = []
        text = self.inspect_certificate(certificate)
        san_text = self.run("x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName")
        present_dns = {value.lower() for value in re.findall(r"DNS:([^,\s]+)", san_text, re.IGNORECASE)}
        present_ips = set()
        for value in re.findall(r"IP Address:([^,\s]+)", san_text, re.IGNORECASE):
            try:
                present_ips.add(ipaddress.ip_address(value))
            except ValueError:
                pass
        if "CA:FALSE" not in text:
            raise OpenSSLError("The leaf certificate is not marked CA:FALSE.")
        if "TLS Web Server Authentication" not in text:
            raise OpenSSLError("The leaf certificate does not contain serverAuth EKU.")
        if "Digital Signature" not in text or "Key Encipherment" not in text:
            raise OpenSSLError("The leaf certificate does not have the required HTTPS key usage.")
        if not self.verify_key_matches(certificate, private_key, key_password):
            raise OpenSSLError("The private key does not match the certificate.")
        self.verify_chain(certificate, ca_chain)
        for san in normalize_sans(requested_sans):
            if san.startswith("IP:"):
                if ipaddress.ip_address(san[3:]) not in present_ips:
                    raise OpenSSLError(f"The requested SAN is missing from the certificate: {san}")
            else:
                if san[4:].lower() not in present_dns:
                    raise OpenSSLError(f"The requested SAN is missing from the certificate: {san}")
        checks.extend(("Certificate/private key match", "Certificate chain valid",
                       "Server Authentication EKU", "CA:FALSE", "SAN validation"))
        return checks

    def generate_csr(self, output: Path, subject: Subject, sans: Iterable[str], password: str,
                     key_type: str = "RSA", key_size_or_curve: str = "RSA 3072",
                     digest: str = "SHA-256", application_uri: str = "",
                     existing_key: Path | None = None) -> tuple[Path, Path]:
        output.mkdir(parents=True, exist_ok=True)
        key = output / "private-key.pem"
        csr = output / "request.csr.pem"
        for target in (csr,):
            if target.exists():
                raise FileExistsError(f"Refusing to overwrite existing file: {target}")
        if existing_key is None and key.exists():
            raise FileExistsError(f"Refusing to overwrite existing file: {key}")
        if existing_key is not None:
            if not existing_key.exists():
                raise FileNotFoundError(f"Existing private key not found: {existing_key}")
            if not key.exists():
                shutil.copy2(existing_key, key)
        san_values = normalize_sans(sans)
        if existing_key is None:
            key_args = _keygen_args(key_type, key_size_or_curve)
            if password:
                key_args += ["-aes-256-cbc", "-pass", "file:{PASSFILE}"]
            key_args += ["-out", str(key)]
            self.run(*key_args, password=password if password else None)
        args = ["req", "-new", f"-{_digest_name(digest)}", "-key", str(key), "-out", str(csr), "-subj", subject.openssl_subject()]
        if san_values or application_uri:
            all_sans = list(san_values)
            if application_uri:
                all_sans.append(f"URI:{normalize_application_uri(application_uri)}")
            args += ["-addext", f"subjectAltName={','.join(all_sans)}"]
        if password:
            args += ["-passin", "file:{PASSFILE}"]
            self.run(*args, password=password)
        else:
            self.run(*args)
        return key, csr

    def create_pki(self, workspace: Path, root_subject: Subject, intermediate_subject: Subject, password: str,
                   root_days: int = 5475, intermediate_days: int = 3650,
                   key_type: str = "RSA", key_size_or_curve: str = "RSA 3072",
                   digest: str = "SHA-256") -> dict[str, Path]:
        if root_days <= intermediate_days:
            raise ValueError("The root CA validity must be longer than the intermediate CA validity.")
        root = workspace / "root-ca"
        intermediate = workspace / "intermediate-ca"
        for folder in (root, intermediate):
            (folder / "private").mkdir(parents=True, exist_ok=True)
            (folder / "certs").mkdir(exist_ok=True)
        root_key, root_cert = root / "private" / "root-ca.key.pem", root / "certs" / "root-ca.cert.pem"
        int_key, int_csr, int_cert = intermediate / "private" / "intermediate-ca.key.pem", intermediate / "intermediate-ca.csr.pem", intermediate / "certs" / "intermediate-ca.cert.pem"
        for target in (root_key, root_cert, int_key, int_csr, int_cert):
            if target.exists():
                raise FileExistsError(f"Refusing to overwrite existing PKI file: {target}")
        digest_name = _digest_name(digest)
        root_key_args = _keygen_args(key_type, key_size_or_curve)
        if password: root_key_args += ["-aes-256-cbc", "-pass", "file:{PASSFILE}"]
        root_key_args += ["-out", str(root_key)]
        self.run(*root_key_args, password=password if password else None)
        root_req_args = ["req", "-x509", "-new", f"-{digest_name}", "-key", str(root_key)]
        if password: root_req_args += ["-passin", "file:{PASSFILE}"]
        root_req_args += ["-days", str(root_days), "-subj", root_subject.openssl_subject(), "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(root_cert)]
        self.run(*root_req_args, password=password if password else None)
        int_key_args = _keygen_args(key_type, key_size_or_curve)
        if password: int_key_args += ["-aes-256-cbc", "-pass", "file:{PASSFILE}"]
        int_key_args += ["-out", str(int_key)]
        self.run(*int_key_args, password=password if password else None)
        int_req_args = ["req", "-new", f"-{digest_name}", "-key", str(int_key)]
        if password: int_req_args += ["-passin", "file:{PASSFILE}"]
        int_req_args += ["-subj", intermediate_subject.openssl_subject(), "-out", str(int_csr)]
        self.run(*int_req_args, password=password if password else None)
        ext = workspace / "intermediate-ca.ext"
        ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n", encoding="utf-8")
        sign_args = ["x509", "-req", "-in", str(int_csr), "-CA", str(root_cert), "-CAkey", str(root_key)]
        if password: sign_args += ["-passin", "file:{PASSFILE}"]
        sign_args += ["-CAcreateserial", "-days", str(intermediate_days), f"-{digest_name}", "-extfile", str(ext), "-out", str(int_cert)]
        self.run(*sign_args, password=password if password else None)
        chain = intermediate / "certs" / "ca-chain.pem"
        chain.write_bytes(int_cert.read_bytes() + root_cert.read_bytes())
        trust = create_trust_bundle(workspace / "trust-installers", root_cert, int_cert)
        return {"root_certificate": root_cert, "intermediate_certificate": int_cert, "chain": chain, **trust}

    def verify_ca_password(self, ca_key: Path, password: str) -> None:
        """Raise a clear error before any output is written if `password` cannot
        decrypt `ca_key`, instead of failing partway through issuance.

        Any failure here is treated as a wrong password rather than pattern-matched
        against OpenSSL's error text, which varies by command and OpenSSL version
        (compare the cipher-level "bad decrypt" from `x509 -CAkey` with the
        decoder-level "No supported data to decode" from `pkey`). The file's
        existence and encryption already ruled out the other failure modes.
        """
        if not is_encrypted_private_key(ca_key):
            return
        if not password:
            raise ValueError("This project uses encrypted CA keys; enter the CA password to continue.")
        try:
            self.run("pkey", "-in", str(ca_key), "-noout", "-passin", "file:{PASSFILE}", password=password)
        except OpenSSLError as exc:
            if "Incorrect password" not in str(exc):
                self.logger(str(exc))
            raise OpenSSLError(
                "Incorrect password: OpenSSL could not decrypt the CA private key with "
                "the password you entered. Verify the password and try again. The full "
                "OpenSSL error was written to the activity log."
            ) from None

    def issue_server(self, workspace: Path, output: Path, subject: Subject, sans: Iterable[str],
                     ca_password: str, key_password: str,
                     profile: CertificateProfile = PROFILES["flexedge_https"],
                     days: int | None = None, digest: str = "SHA-256",
                     key_type: str = "RSA", key_size_or_curve: str = "RSA 3072",
                     application_uri: str = "", existing_key: Path | None = None,
                     reissue: str | None = None) -> dict[str, Path]:
        int_key = workspace / "intermediate-ca" / "private" / "intermediate-ca.key.pem"
        int_cert = workspace / "intermediate-ca" / "certs" / "intermediate-ca.cert.pem"
        root_cert = workspace / "root-ca" / "certs" / "root-ca.cert.pem"
        for needed in (int_key, int_cert, root_cert):
            if not needed.exists():
                raise FileNotFoundError(f"PKI file not found: {needed}")
        self.verify_ca_password(int_key, ca_password)
        output.mkdir(parents=True, exist_ok=True)
        archive: Path | None = None
        if reissue is not None:
            existing_key, archive = self._prepare_reissue(output, reissue)
        names = ("request.csr.pem", "certificate.pem", "fullchain.pem")
        if existing_key is None:
            names = ("private-key.pem",) + names
        for name in names:
            if (output / name).exists():
                raise FileExistsError(f"Refusing to overwrite existing device file: {output / name}")
        requested_days = days or profile.default_days
        remaining_days = (self.certificate_not_after(int_cert) - datetime.now(timezone.utc)).days
        if requested_days > remaining_days + 1:
            raise ValueError(f"Requested certificate validity exceeds the issuing CA lifetime. Maximum remaining validity is {remaining_days} days.")
        effective_days = min(requested_days, remaining_days)
        key, csr = self.generate_csr(output, subject, sans, key_password,
                                     key_type, key_size_or_curve, digest, application_uri, existing_key)
        cert = output / "certificate.pem"
        ext = output / "certificate.ext"
        san_values = normalize_sans(sans)
        if application_uri:
            san_values.append(f"URI:{normalize_application_uri(application_uri)}")
        if not san_values:
            raise ValueError("At least one Subject Alternative Name is required.")
        ext.write_text("\n".join(("basicConstraints=critical,CA:FALSE", f"keyUsage=critical,{','.join(profile.key_usage)}", f"extendedKeyUsage={','.join(profile.extended_key_usage)}", f"subjectAltName={','.join(san_values)}", "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid,issuer")) + "\n", encoding="utf-8")
        sign_args = ["x509", "-req", "-in", str(csr), "-CA", str(int_cert), "-CAkey", str(int_key)]
        if ca_password: sign_args += ["-passin", "file:{PASSFILE}"]
        sign_args += ["-CAcreateserial", "-days", str(effective_days), f"-{_digest_name(digest)}", "-extfile", str(ext), "-out", str(cert)]
        self.run(*sign_args, password=ca_password if ca_password else None)
        chain = output / "ca-chain.pem"
        chain.write_bytes(int_cert.read_bytes() + root_cert.read_bytes())
        intermediate_out = output / "intermediate-ca.pem"
        root_out = output / "root-ca.pem"
        fullchain = output / "fullchain.pem"
        intermediate_out.write_bytes(int_cert.read_bytes())
        root_out.write_bytes(root_cert.read_bytes())
        fullchain.write_bytes(cert.read_bytes() + int_cert.read_bytes())
        report = output / "certificate-report.txt"
        report.write_text(self.inspect_certificate(cert) + "\n\n" + self.verify_chain(cert, chain) + "\n", encoding="utf-8")
        trust = create_trust_bundle(output / "trust-installers", root_cert, int_cert)
        result = {"certificate": cert, "private_key": key, "ca_chain": chain, "fullchain": fullchain,
                "intermediate": intermediate_out, "root": root_out, "csr": csr, "report": report, **trust}
        if archive:
            result["archive"] = archive
        return result

    def issue_ram_https(self, workspace: Path, output: Path, subject: Subject,
                        sans: Iterable[str], ca_password: str, key_password: str,
                        days: int | None = None, reissue: str = "new") -> dict[str, Path]:
        profile = PROFILES["ram_https"]
        existing_key = output / "private-key.pem"
        archive_path: Path | None = None
        if output.exists() and any(path for path in output.iterdir() if path.name != "archive"):
            if reissue not in {"existing", "new"}:
                raise ValueError("RAM reissue mode must be 'existing' or 'new'.")
            archive_path = output / "archive" / datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            archive_path.mkdir(parents=True, exist_ok=False)
            for path in list(output.iterdir()):
                if path.name == "archive" or (reissue == "existing" and path == existing_key):
                    continue
                shutil.move(str(path), archive_path / path.name)
        elif reissue != "new":
            raise ValueError("Cannot reuse a private key because no existing RAM issuance was found.")
        result = self.issue_server(
            workspace, output, subject, sans, ca_password, key_password,
            profile=profile, days=days, digest=profile.leaf_digest or "SHA-256",
            key_type=profile.leaf_key_type or "RSA",
            key_size_or_curve=profile.leaf_key_size_or_curve or "RSA 2048",
            existing_key=existing_key if reissue == "existing" else None,
        )
        rsa_key = output / "private-key-rsa.pem"
        self.run("rsa", "-in", str(result["private_key"]), "-out", str(rsa_key), "-traditional",
                 *(["-passin", "file:{PASSFILE}"] if key_password else []),
                 password=key_password if key_password else None)
        deployment = output / "ram-https.pem"
        deployment.write_bytes(result["fullchain"].read_bytes() + rsa_key.read_bytes())
        lighttpd = output / "lighttpd-gau.pem"
        lighttpd.write_bytes(deployment.read_bytes())
        deployment_certs = split_pem_certificates(deployment.read_bytes())
        if len(deployment_certs) != 2 or b"BEGIN RSA PRIVATE KEY" not in deployment.read_bytes():
            raise OpenSSLError("RAM deployment PEM must contain leaf, intermediate, and traditional RSA key.")
        if result["root"].read_bytes() in deployment.read_bytes():
            raise OpenSSLError("The root CA must not be included in the RAM deployment PEM.")
        self.validate_server_certificate(result["certificate"], rsa_key, result["ca_chain"], sans)
        issuer_expiry = self.certificate_not_after(result["intermediate"])
        root_inspection = self.inspect_certificate(result["root"])
        fingerprint_match = re.search(r"sha256 Fingerprint=([^\r\n]+)", root_inspection, re.IGNORECASE)
        root_fingerprint = fingerprint_match.group(1) if fingerprint_match else "Unavailable"
        report = output / "certificate-report.txt"
        report.write_text(
            "Profile: Red Lion RAM HTTPS Server\n"
            f"Device: {subject.common_name}\nCommon Name: {subject.common_name}\n"
            f"SANs: {', '.join(normalize_sans(sans))}\nLeaf Key: RSA 2048\n"
            "Leaf Signature: SHA-256\n"
            f"Issuing CA: {result['intermediate'].name}\nRoot CA: {result['root'].name}\n"
            f"Root CA SHA-256 fingerprint: {root_fingerprint}\n"
            f"Issuing CA expiration: {issuer_expiry.isoformat()}\n"
            "Deployment key format: PKCS#1 Traditional RSA\n"
            "Deployment PEM: ram-https.pem\nDeployment PEM contents: Leaf certificate, Intermediate certificate, RSA private key\n"
            "Root included in deployment PEM: No\nCertificate/private key match: PASS\nChain verification: PASS\n"
            "SAN validation: PASS\nRAM deployment validation: PASS\n\n"
            + self.inspect_certificate(result["certificate"]) + "\n\n"
            + self.verify_chain(result["certificate"], result["ca_chain"]) + "\n",
            encoding="utf-8",
        )
        readme = output / "README-RAM-HTTPS.txt"
        readme.write_text(
            "RED LION RAM HTTPS CERTIFICATE\n\n"
            f"Device: {subject.common_name}\nCertificate Common Name: {subject.common_name}\n"
            f"Certificate identities: {', '.join(normalize_sans(sans))}\n\n"
            "INSTALL CLIENT TRUST FIRST\n\nInstall root-ca.pem into Trusted Root Certification Authorities.\n"
            "Install intermediate-ca.pem into Intermediate Certification Authorities if required.\n"
            "Do NOT install the RAM private key on administrative computers.\n\n"
            "RAM INSTALLATION\n\n1. Log into the RAM web interface.\n2. Navigate to Admin -> Certificates.\n"
            "3. Select Add Certificate.\n4. Select Certificate Type: HTTPS.\n5. Upload ram-https.pem.\n\n"
            "The deployment PEM contains the server certificate, intermediate CA, and RSA private key.\n"
            "The root CA is intentionally excluded. This file contains the RAM HTTPS private key; protect it as sensitive device credential material.\n",
            encoding="utf-8",
        )
        result.update(private_key_rsa=rsa_key, ram_https=deployment, lighttpd_gau=lighttpd,
                      readme_ram_https=readme, report=report)
        if archive_path:
            result["archive"] = archive_path
        return result

    @staticmethod
    def _rename_profile_files(result: dict[str, Path], output: Path, prefix: str) -> dict[str, Path]:
        mapping = {
            "certificate": f"{prefix}-certificate.pem",
            "private_key": f"{prefix}-private-key.pem",
            "fullchain": f"{prefix}-fullchain.pem",
            "csr": f"{prefix}-request.csr.pem",
        }
        for key, name in mapping.items():
            old = result[key]
            new = output / name
            old.rename(new)
            result[key] = new
        ext = output / "certificate.ext"
        if ext.exists():
            renamed = output / f"{prefix}-certificate.ext"
            ext.rename(renamed)
            result["extensions"] = renamed
        return result

    @staticmethod
    def _prepare_reissue(output: Path, reissue: str, key_name: str = "private-key.pem") -> tuple[Path | None, Path | None]:
        if reissue not in {"new", "existing"}:
            raise ValueError("Reissue mode must be 'new' or 'existing'.")
        if not output.exists() or not any(path.name != "archive" for path in output.iterdir()):
            if reissue == "existing":
                raise ValueError("Cannot reuse a private key because no existing issuance was found.")
            return None, None
        archive = output / "archive" / datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        archive.mkdir(parents=True, exist_ok=False)
        old_key = output / key_name
        if reissue == "existing" and not old_key.exists():
            raise FileNotFoundError(f"Existing private key not found: {old_key}")
        for path in list(output.iterdir()):
            if path.name != "archive":
                shutil.move(str(path), archive / path.name)
        existing_key = archive / key_name if reissue == "existing" else None
        return existing_key, archive

    def issue_mqtt_broker(self, workspace: Path, output: Path, subject: Subject,
                          sans: Iterable[str], ca_password: str, key_password: str,
                          mutual_tls: bool = False, reissue: str = "new", **kwargs) -> dict[str, Path]:
        existing_key, archive = self._prepare_reissue(output, reissue, "broker-private-key.pem")
        result = self.issue_server(workspace, output, subject, sans, ca_password, key_password,
                                   profile=PROFILES["mqtt_broker"], existing_key=existing_key, **kwargs)
        self._rename_profile_files(result, output, "broker")
        conf = output / "mosquitto-tls.conf"
        conf.write_text(
            "listener 8883\nallow_anonymous false\n"
            "cafile /etc/mosquitto/certs/ca-chain.pem\n"
            "certfile /etc/mosquitto/certs/broker-certificate.pem\n"
            "keyfile /etc/mosquitto/certs/broker-private-key.pem\n"
            f"require_certificate {'true' if mutual_tls else 'false'}\n"
            f"use_identity_as_username {'true' if mutual_tls else 'false'}\n",
            encoding="utf-8",
        )
        install = output / "install-mosquitto-tls.sh"
        install.write_text("""#!/usr/bin/env bash
set -euo pipefail
echo "Back up /etc/mosquitto before installing."
sudo install -d -m 0750 /etc/mosquitto/certs
sudo install -m 0644 broker-certificate.pem ca-chain.pem /etc/mosquitto/certs/
sudo install -m 0640 broker-private-key.pem /etc/mosquitto/certs/
sudo install -m 0644 mosquitto-tls.conf /etc/mosquitto/conf.d/
sudo mosquitto -c /etc/mosquitto/mosquitto.conf -t
echo "Restart Mosquitto only after validation; restore the backup on failure."
""", encoding="utf-8")
        remove = output / "remove-mosquitto-tls.sh"
        remove.write_text("""#!/usr/bin/env bash
set -euo pipefail
read -r -p "Type REMOVE to continue: " answer
[[ "$answer" == "REMOVE" ]] || exit 1
sudo rm -f /etc/mosquitto/conf.d/mosquitto-tls.conf
echo "Restore the previous configuration from backup if required."
""", encoding="utf-8")
        verify = output / "verify-mqtt-tls.sh"
        verify.write_text("""#!/usr/bin/env bash
set -euo pipefail
openssl s_client -connect "${1:-localhost}:8883" -CAfile ca-chain.pem </dev/null
echo "Then verify publish/subscribe with mosquitto_pub and mosquitto_sub."
""", encoding="utf-8")
        for path in (install, remove, verify):
            path.chmod(0o755)
        result.update(mosquitto_conf=conf, mosquitto_install=install,
                      mosquitto_remove=remove, mosquitto_verify=verify)
        if archive:
            result["archive"] = archive
        return result

    def issue_mqtt_client(self, workspace: Path, output: Path, subject: Subject,
                          sans: Iterable[str], ca_password: str, key_password: str,
                          reissue: str = "new", **kwargs) -> dict[str, Path]:
        existing_key, archive = self._prepare_reissue(output, reissue, "client-private-key.pem")
        result = self.issue_server(workspace, output, subject, sans, ca_password, key_password,
                                   profile=PROFILES["mqtt_client"], existing_key=existing_key, **kwargs)
        result = self._rename_profile_files(result, output, "client")
        if archive:
            result["archive"] = archive
        return result

    def generate_intermediate_crl(self, workspace: Path, ca_password: str,
                                  days: int = 365) -> dict[str, Path]:
        int_dir = workspace / "intermediate-ca"
        int_key = int_dir / "private" / "intermediate-ca.key.pem"
        int_cert = int_dir / "certs" / "intermediate-ca.cert.pem"
        if is_encrypted_private_key(int_key) and not ca_password:
            raise ValueError("This project uses encrypted CA keys; enter the CA password to generate a CRL.")
        state = int_dir / "crl"
        new_certs = state / "newcerts"
        new_certs.mkdir(parents=True, exist_ok=True)
        index = state / "index.txt"
        serial = state / "serial"
        crlnumber = state / "crlnumber"
        if not index.exists():
            index.write_text("", encoding="ascii")
        if not serial.exists():
            serial.write_text("1000\n", encoding="ascii")
        if not crlnumber.exists():
            crlnumber.write_text("1000\n", encoding="ascii")
        config = state / "openssl-crl.cnf"
        config.write_text(
            "[ ca ]\ndefault_ca = CA_default\n[ CA_default ]\n"
            f'database = "{index.as_posix()}"\nnew_certs_dir = "{new_certs.as_posix()}"\n'
            f'certificate = "{int_cert.as_posix()}"\nprivate_key = "{int_key.as_posix()}"\n'
            f'serial = "{serial.as_posix()}"\ncrlnumber = "{crlnumber.as_posix()}"\n'
            "default_md = sha256\ndefault_crl_days = " + str(days) + "\n"
            "policy = policy_any\n[ policy_any ]\ncommonName = supplied\n",
            encoding="utf-8",
        )
        pem = state / "intermediate-ca.crl.pem"
        der = state / "intermediate-ca.crl.der"
        args = ["ca", "-gencrl", "-config", str(config), "-out", str(pem)]
        if ca_password:
            args += ["-passin", "file:{PASSFILE}"]
        self.run(*args, password=ca_password if ca_password else None)
        self.run("crl", "-in", str(pem), "-outform", "DER", "-out", str(der))
        self.run("crl", "-in", str(pem), "-noout", "-issuer", "-lastupdate", "-nextupdate")
        return {"crl_pem": pem, "crl_der": der}

    def _issue_opcua(self, workspace: Path, output: Path, subject: Subject,
                     sans: Iterable[str], application_uri: str,
                     ca_password: str, key_password: str,
                     profile: CertificateProfile, prefix: str, role_label: str,
                     reissue: str = "new", **kwargs) -> dict[str, Path]:
        uri = normalize_application_uri(application_uri)
        existing_key, archive = self._prepare_reissue(output, reissue, f"{prefix}-private-key.pem")
        result = self.issue_server(workspace, output, subject, sans, ca_password, key_password,
                                   profile=profile, application_uri=uri,
                                   existing_key=existing_key, **kwargs)
        self._rename_profile_files(result, output, prefix)
        crls = self.generate_intermediate_crl(workspace, ca_password)
        trust = output / "opcua-trust"
        trusted = trust / "trusted" / "certs"
        issuers = trust / "issuers" / "certs"
        crl_dir = trust / "issuers" / "crl"
        for folder in (trusted, issuers, crl_dir):
            folder.mkdir(parents=True, exist_ok=True)
        root_der = trusted / "root-ca.der"
        int_der = issuers / "intermediate-ca.der"
        crl_der = crl_dir / "intermediate-ca.crl.der"
        crl_pem = crl_dir / "intermediate-ca.crl.pem"
        self.run("x509", "-in", str(result["root"]), "-outform", "DER", "-out", str(root_der))
        self.run("x509", "-in", str(result["intermediate"]), "-outform", "DER", "-out", str(int_der))
        shutil.copy2(crls["crl_der"], crl_der)
        shutil.copy2(crls["crl_pem"], crl_pem)
        leaf_der = output / f"{prefix}-certificate.der"
        self.run("x509", "-in", str(result["certificate"]), "-outform", "DER", "-out", str(leaf_der))
        guide = output / "OPC-UA-INSTALLATION.txt"
        guide.write_text(
            f"OPC UA {role_label} certificate package\n\n"
            f"Application URI: {uri}\n"
            f"1. Install {prefix}-certificate.pem and {prefix}-private-key.pem as the {role_label} application identity.\n"
            "2. Install the issuing chain and CRL in the OPC UA trust stores, not only the HTTPS identity store.\n"
            "3. Trust the counterpart OPC UA application certificate on each endpoint it connects to.\n"
            "4. On UAExpert/PI, place trusted and issuer files according to the supplied opcua-trust tree.\n"
            "5. Confirm the endpoint ApplicationUri exactly matches the URI SAN above.\n"
            "6. Test Basic256Sha256 and inspect the precise Bad_* status before production rollout.\n",
            encoding="utf-8",
        )
        report = result["report"]
        report.write_text(
            f"Profile: OPC UA {role_label}\nApplication URI: " + uri + "\n"
            "CRL (PEM): " + str(crl_pem) + "\nCRL (DER): " + str(crl_der) + "\n\n"
            + report.read_text(encoding="utf-8"), encoding="utf-8")
        result.update(crl_pem=crl_pem, crl_der=crl_der,
                      root_der=root_der, intermediate_der=int_der,
                      certificate_der=leaf_der, installation_guide=guide)
        if archive:
            result["archive"] = archive
        return result

    def issue_opcua_server(self, workspace: Path, output: Path, subject: Subject,
                           sans: Iterable[str], application_uri: str,
                           ca_password: str, key_password: str,
                           reissue: str = "new", **kwargs) -> dict[str, Path]:
        return self._issue_opcua(workspace, output, subject, sans, application_uri,
                                 ca_password, key_password, PROFILES["opcua_server"],
                                 "server", "server", reissue=reissue, **kwargs)

    def issue_opcua_client(self, workspace: Path, output: Path, subject: Subject,
                           sans: Iterable[str], application_uri: str,
                           ca_password: str, key_password: str,
                           reissue: str = "new", **kwargs) -> dict[str, Path]:
        return self._issue_opcua(workspace, output, subject, sans, application_uri,
                                 ca_password, key_password, PROFILES["opcua_client"],
                                 "client", "client", reissue=reissue, **kwargs)

    def package_existing(self, certificate: Path, private_key: Path, ca_chain: Path,
                         output: Path, key_password: str = "") -> dict[str, Path]:
        if is_encrypted_private_key(private_key) and not key_password:
            raise ValueError("The selected private key is encrypted; enter its password to continue.")
        if not self.verify_key_matches(certificate, private_key, key_password):
            raise OpenSSLError("The private key does not match the certificate.")
        self.verify_chain(certificate, ca_chain)
        output.mkdir(parents=True, exist_ok=True)
        if any(output.iterdir()):
            raise FileExistsError(f"The package folder must be empty: {output}")
        cert_out, key_out, chain_out = output / "certificate.pem", output / "private-key.pem", output / "ca-chain.pem"
        shutil.copy2(certificate, cert_out); shutil.copy2(private_key, key_out); shutil.copy2(ca_chain, chain_out)
        # The supplied chain is expected to be ordered intermediate(s), then
        # root. Browsers already possess the trusted root, so fullchain.pem
        # contains the leaf and intermediates, but not the final root.
        chain_certificates = split_pem_certificates(chain_out.read_bytes())
        intermediates = chain_certificates[:-1]
        fullchain = output / "fullchain.pem"
        fullchain.write_bytes(cert_out.read_bytes() + b"".join(intermediates))
        report = output / "certificate-report.txt"
        report.write_text(self.inspect_certificate(cert_out) + "\n\n" + self.verify_chain(cert_out, chain_out) + "\n", encoding="utf-8")
        root = output / "root-ca.pem"; root.write_bytes(chain_certificates[-1])
        intermediate = None
        if intermediates:
            intermediate = output / "intermediate-ca.pem"; intermediate.write_bytes(b"".join(intermediates))
        trust = create_trust_bundle(output / "trust-installers", root, intermediate)
        return {"certificate": cert_out, "private_key": key_out, "ca_chain": chain_out,
                "fullchain": fullchain, "root": root, "report": report, **trust}

    def export_pkcs12(self, certificate: Path, private_key: Path, ca_chain: Path, output: Path,
                      pfx_password: str, key_password: str = "") -> Path:
        """Bundle `certificate` + `private_key` + `ca_chain` into a password-protected
        .pfx, for applications (Kepware, IIS, ...) that import PKCS#12 instead of
        separate PEM files. `key_password` decrypts `private_key` if it is itself
        encrypted; `pfx_password` protects the resulting .pfx and may be different."""
        args = ["pkcs12", "-export", "-in", str(certificate), "-inkey", str(private_key),
                "-certfile", str(ca_chain), "-out", str(output), "-passout", "file:{PASSOUT}"]
        passwords = {"{PASSOUT}": pfx_password}
        if is_encrypted_private_key(private_key):
            args += ["-passin", "file:{PASSIN}"]
            passwords["{PASSIN}"] = key_password
        self._run(*args, passwords=passwords)
        return output
