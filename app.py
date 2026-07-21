# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ipaddress
import re
import secrets
import sys
from pathlib import Path

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtWidgets import (QApplication, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QStackedWidget, QInputDialog, QCheckBox,
    QTextEdit, QVBoxLayout, QWidget, QScrollArea, QFrame, QButtonGroup, QSizePolicy)

from ica.openssl_engine import OpenSSLEngine, OpenSSLError, Subject
from ica.project import Project, safe_name
from ica.trust_scripts import create_trust_bundle
from ica import __version__


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.project: Project | None = None
        self.setWindowTitle(f"Industrial Certificate Assistant {__version__}")
        self.resize(1180, 780)
        self.setMinimumSize(940, 650)
        self.log = QTextEdit(readOnly=True)
        self.log.setObjectName("activityLog")
        try:
            self.engine = OpenSSLEngine(logger=self.log.append)
            status = self.engine.version()
        except Exception as exc:
            self.engine = None; status = f"OpenSSL unavailable: {exc}"
        root = QWidget(); root.setObjectName("appRoot")
        layout = QVBoxLayout(root); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)

        masthead = QFrame(); masthead.setObjectName("masthead")
        masthead_layout = QHBoxLayout(masthead); masthead_layout.setContentsMargins(20, 10, 18, 10)
        brand = QVBoxLayout(); brand.setSpacing(1)
        title = QLabel("Industrial Certificate Assistant"); title.setObjectName("brandTitle")
        subtitle = QLabel("Guided SSL/TLS Management for Crimson 3.2 Devices"); subtitle.setObjectName("brandSubtitle")
        brand.addWidget(title); brand.addWidget(subtitle)
        masthead_layout.addLayout(brand); masthead_layout.addStretch(1)
        version = QLabel(f"Version {__version__}"); version.setObjectName("versionBadge")
        masthead_layout.addWidget(version)
        layout.addWidget(masthead)

        body = QWidget(); body_layout = QHBoxLayout(body); body_layout.setContentsMargins(0, 0, 0, 0); body_layout.setSpacing(0)
        nav = QFrame(); nav.setObjectName("navigationRail"); nav.setFixedWidth(152)
        nav_layout = QVBoxLayout(nav); nav_layout.setContentsMargins(8, 12, 8, 10); nav_layout.setSpacing(7)

        self.pages = QStackedWidget(); self.pages.setObjectName("workflowPages")
        page_definitions = (
            ("IMPORT", "Existing\ncertificate", self.import_page),
            ("REQUEST", "Company\nrequest", self.csr_page),
            ("PKI", "Create\nprivate PKI", self.pki_page),
            ("DEVICE", "Issue device\ncertificate", self.issue_page),
        )
        self.nav_group = QButtonGroup(self); self.nav_group.setExclusive(True)
        for index, (icon, label, factory) in enumerate(page_definitions):
            button = QPushButton(f"{icon}\n{label}")
            button.setObjectName("navButton"); button.setCheckable(True); button.setMinimumHeight(82)
            button.clicked.connect(lambda _=False, p=index: self.pages.setCurrentIndex(p))
            self.nav_group.addButton(button, index); nav_layout.addWidget(button)
            self.pages.addWidget(self.scrollable(factory()))
        self.nav_group.button(0).setChecked(True)
        nav_layout.addStretch(1)
        help_label = QLabel("SSL/TLS\nTools"); help_label.setObjectName("railFooter"); help_label.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(help_label)
        body_layout.addWidget(nav)

        workspace = QWidget(); workspace.setObjectName("workspace")
        workspace_layout = QVBoxLayout(workspace); workspace_layout.setContentsMargins(14, 12, 14, 10); workspace_layout.setSpacing(8)
        self.project_status = QLabel("No project loaded")
        self.project_status.setObjectName("projectStatus")
        status_row = QFrame(); status_row.setObjectName("statusStrip")
        status_layout = QHBoxLayout(status_row); status_layout.setContentsMargins(10, 6, 10, 6)
        status_layout.addWidget(QLabel(status)); status_layout.addStretch(1); status_layout.addWidget(self.project_status)
        workspace_layout.addWidget(status_row)
        workspace_layout.addWidget(self.pages, 1)
        log_title = QLabel("Activity log    •    Passwords and private-key contents are never logged")
        log_title.setObjectName("sectionHeader")
        workspace_layout.addWidget(log_title); workspace_layout.addWidget(self.log, 0)
        self.log.setMinimumHeight(135); self.log.setMaximumHeight(190)
        body_layout.addWidget(workspace, 1); layout.addWidget(body, 1)

        footer = QFrame(); footer.setObjectName("footer")
        footer_layout = QHBoxLayout(footer); footer_layout.setContentsMargins(12, 4, 12, 4)
        footer_layout.addWidget(QLabel("Industrial Certificate Assistant")); footer_layout.addStretch(1)
        footer_layout.addWidget(QLabel("PKI workspace and private keys remain on this computer"))
        layout.addWidget(footer)
        self.setCentralWidget(root)
        self.setStyleSheet(self.application_stylesheet())

    @staticmethod
    def application_stylesheet():
        return """
        QWidget#appRoot, QWidget#workspace { background: #f3f4f6; color: #17202a; }
        QFrame#masthead { background: #074764; border-bottom: 1px solid #03364d; }
        QLabel#brandTitle { color: white; font-size: 25px; font-weight: 600; }
        QLabel#brandSubtitle { color: #d9edf5; font-size: 12px; }
        QLabel#versionBadge { color: white; background: #0b5d7d; border: 1px solid #5c90a5;
            border-radius: 2px; padding: 5px 10px; }
        QFrame#navigationRail { background: #eceeef; border-right: 1px solid #c1c7cc; }
        QPushButton#navButton { background: transparent; color: #17202a; border: 1px solid transparent;
            border-radius: 2px; padding: 7px 4px; font-size: 12px; text-align: center; }
        QPushButton#navButton:hover { background: #dbe7ec; border-color: #9fb8c3; }
        QPushButton#navButton:checked { background: #ffffff; color: #074764; border: 1px solid #9aa8ae;
            border-left: 5px solid #074764; font-weight: 600; }
        QLabel#railFooter { color: #5f6b72; border-top: 1px solid #c5cbd0; padding-top: 10px; }
        QFrame#statusStrip { background: #ffffff; border: 1px solid #c9ced2; }
        QLabel#projectStatus { color: #66737b; font-weight: 600; }
        QLabel#pageTitle, QLabel#sectionHeader { background: #074764; color: white; padding: 7px 10px;
            font-size: 15px; font-weight: 600; }
        QLabel#pageDescription { color: #5d6970; padding: 3px 2px 7px 2px; }
        QFrame#contentPanel { background: #ffffff; border: 1px solid #c5cbd0; }
        QFrame#contentPanel QLabel { background: transparent; }
        QLineEdit, QTextEdit { background: #ffffff; color: #17202a; border: 1px solid #9da8ae;
            border-radius: 1px; padding: 5px; selection-background-color: #0b668d; }
        QLineEdit:focus, QTextEdit:focus { border: 1px solid #0b668d; }
        QLineEdit:read-only { background: #edf0f2; color: #53616a; }
        QPushButton { background: #ffffff; color: #17202a; border: 1px solid #9ca6ac;
            border-radius: 2px; padding: 6px 12px; }
        QPushButton:hover { background: #e9f1f4; border-color: #397a94; }
        QPushButton[action="primary"] { background: #0b5675; color: white; border-color: #063e56;
            font-weight: 600; padding: 8px 15px; }
        QPushButton[action="primary"]:hover { background: #0d688e; }
        QCheckBox { spacing: 7px; }
        QScrollArea { background: #f3f4f6; border: 0; }
        QTextEdit#activityLog { background: #ffffff; color: #26343b; border: 1px solid #aeb7bc;
            font-family: Consolas, "Liberation Mono", monospace; font-size: 11px; }
        QFrame#footer { background: #eceeef; border-top: 1px solid #bdc5ca; color: #59656c; }
        QToolTip { background: #fff; color: #17202a; border: 1px solid #6f7d84; }
        """

    @staticmethod
    def workflow_page(title_text, description):
        page = QWidget(); page.setObjectName("page")
        outer = QVBoxLayout(page); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(7)
        title = QLabel(title_text); title.setObjectName("pageTitle")
        detail = QLabel(description); detail.setObjectName("pageDescription"); detail.setWordWrap(True)
        panel = QFrame(); panel.setObjectName("contentPanel")
        form = QFormLayout(panel); form.setContentsMargins(16, 14, 16, 16); form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        outer.addWidget(title); outer.addWidget(detail); outer.addWidget(panel); outer.addStretch(1)
        return page, form

    @staticmethod
    def primary_button(text, handler):
        button = QPushButton(text); button.setProperty("action", "primary")
        button.setMinimumHeight(34); button.clicked.connect(handler)
        return button

    @staticmethod
    def scrollable(page):
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame); scroll.setWidget(page)
        return scroll

    def path_field(self, directory=False, on_change=None):
        row = QWidget(); box = QHBoxLayout(row); box.setContentsMargins(0, 0, 0, 0)
        edit = QLineEdit(); button = QPushButton("Browse…")
        def browse():
            value = QFileDialog.getExistingDirectory(self, "Select folder") if directory else QFileDialog.getOpenFileName(self, "Select file")[0]
            if value:
                edit.setText(value)
                if on_change: on_change(value)
        button.clicked.connect(browse); box.addWidget(edit); box.addWidget(button)
        return row, edit

    @staticmethod
    def password_field():
        field = QLineEdit(); field.setEchoMode(QLineEdit.Password); return field

    def add_new_password_controls(self, form: QFormLayout, description: str):
        protect = QCheckBox(f"Encrypt {description} (recommended)"); protect.setChecked(True)
        password = self.password_field(); confirm = self.password_field()
        controls = QWidget(); row = QHBoxLayout(controls); row.setContentsMargins(0, 0, 0, 0)
        generate = QPushButton("Generate strong password"); show = QCheckBox("Show passwords")
        row.addWidget(generate); row.addWidget(show); row.addStretch(1)
        form.addRow(protect); form.addRow("Password", password); form.addRow("Confirm password", confirm); form.addRow(controls)
        def toggle(enabled):
            password.setEnabled(enabled); confirm.setEnabled(enabled); controls.setEnabled(enabled)
            if not enabled: password.clear(); confirm.clear()
        protect.toggled.connect(toggle)
        generate.clicked.connect(lambda: self.set_generated_password(password, confirm))
        show.toggled.connect(lambda visible: self.show_passwords((password, confirm), visible))
        return protect, password, confirm

    @staticmethod
    def set_generated_password(password, confirm):
        value = secrets.token_urlsafe(24); password.setText(value); confirm.setText(value)

    @staticmethod
    def show_passwords(fields, visible):
        mode = QLineEdit.Normal if visible else QLineEdit.Password
        for field in fields: field.setEchoMode(mode)

    def chosen_password(self, protect, password, confirm, description: str, severe=False) -> str:
        if protect.isChecked():
            if not password.text(): raise ValueError(f"Enter or generate a password for the {description}.")
            if password.text() != confirm.text(): raise ValueError(f"The {description} passwords do not match.")
            return password.text()
        warning = (f"The {description} private key will be stored without encryption. Anyone who obtains the file can use it.\n\n")
        if severe:
            warning += "An unencrypted CA key can issue trusted certificates. This mode is intended only when the customer accepts and controls that risk."
            value, accepted = QInputDialog.getText(self, "Confirm unencrypted CA keys", warning + "\n\nType UNENCRYPTED to continue:")
            if not accepted or value != "UNENCRYPTED": raise ValueError("Unencrypted CA-key creation was cancelled.")
        else:
            answer = QMessageBox.warning(self, "Unencrypted private key", warning + "Continue without a password?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes: raise ValueError("Unencrypted private-key creation was cancelled.")
        return ""

    def import_page(self):
        page, form = self.workflow_page(
            "Use an existing certificate",
            "Validate a certificate and matching private key, add the issuing CA chain, and build a Crimson-ready package.")
        certw, self.icert = self.path_field(); keyw, self.ikey = self.path_field(); caw, self.ica = self.path_field()
        outw, self.iimportout = self.path_field(True); self.ipass = self.password_field()
        form.addRow("Certificate", certw); form.addRow("Private key", keyw); form.addRow("CA chain", caw)
        form.addRow("Private-key password", self.ipass); form.addRow("New Crimson package folder", outw)
        form.addRow(self.primary_button("Validate and create Crimson package", self.validate_import))
        return page

    def csr_page(self):
        page, form = self.workflow_page(
            "Request a certificate from my company",
            "Create a protected private key and certificate-signing request for your organization's certificate authority.")
        projw, self.csrws = self.path_field(True, self.load_project)
        self.csrname = QLineEdit(); self.csrcn = QLineEdit(); self.csrorg = QLineEdit(); self.csrsans = QLineEdit()
        self.csrout = QLineEdit(readOnly=True)
        self.csrname.textChanged.connect(self.update_csr_defaults)
        form.addRow("Project workspace", projw); form.addRow("Request/device name", self.csrname)
        form.addRow("Common name", self.csrcn); form.addRow("Organization", self.csrorg)
        form.addRow("DNS names and IPs (comma-separated)", self.csrsans)
        self.csrprotect, self.csrpass, self.csrpassconfirm = self.add_new_password_controls(form, "CSR private key")
        form.addRow("Automatic output folder", self.csrout)
        form.addRow(self.primary_button("Create private key and certificate request", self.create_csr))
        return page

    def pki_page(self):
        page, form = self.workflow_page(
            "Create a private industrial PKI",
            "Create a root CA, a dedicated industrial-device issuing CA, project folders, and customer trust installers.")
        parentw, self.pkiparent = self.path_field(True, lambda _: self.update_pki_workspace())
        self.pkiname = QLineEdit("Industrial_Certs"); self.pkiorg = QLineEdit(); self.pkidns = QLineEdit("local")
        self.pkiworkspace = QLineEdit(readOnly=True)
        self.pkiname.textChanged.connect(self.update_pki_workspace)
        form.addRow("Parent folder", parentw); form.addRow("Project folder name", self.pkiname)
        form.addRow("Organization", self.pkiorg); form.addRow("Default DNS suffix", self.pkidns)
        form.addRow("Automatic PKI workspace", self.pkiworkspace)
        self.pkiprotect, self.pkipass, self.pkipassconfirm = self.add_new_password_controls(form, "root and intermediate CA private keys")
        note = QLabel("Creates the complete protected folder structure, project metadata, root CA, intermediate CA, and Windows/Linux trust installers. Passwords are not saved.")
        note.setWordWrap(True); form.addRow(note)
        form.addRow(self.primary_button("Create PKI project", self.create_pki))
        return page

    def issue_page(self):
        page, form = self.workflow_page(
            "Issue a Crimson 3.2 device certificate",
            "Issue and package a trusted HTTPS certificate for a FlexEdge device using the loaded PKI project.")
        wsw, self.iws = self.path_field(True, self.load_project)
        self.idevice = QLineEdit(); self.iip = QLineEdit(); self.idns = QLineEdit(); self.iextra = QLineEdit()
        self.icn = QLineEdit(readOnly=True); self.iorg = QLineEdit(readOnly=True); self.isans = QLineEdit(readOnly=True)
        self.iout = QLineEdit(readOnly=True); self.icapass = self.password_field()
        for field in (self.idevice, self.iip, self.idns, self.iextra): field.textChanged.connect(self.update_issue_defaults)
        form.addRow("PKI project workspace", wsw); form.addRow("Device name or serial", self.idevice)
        form.addRow("Device IP address", self.iip); form.addRow("DNS suffix", self.idns)
        form.addRow("Additional DNS names or IPs", self.iextra)
        form.addRow("Automatic common name", self.icn); form.addRow("Organization", self.iorg)
        form.addRow("Automatic Subject Alternative Names", self.isans)
        ca_row = QWidget(); ca_box = QHBoxLayout(ca_row); ca_box.setContentsMargins(0, 0, 0, 0)
        ca_show = QCheckBox("Show"); ca_show.toggled.connect(lambda visible: self.show_passwords((self.icapass,), visible))
        ca_box.addWidget(self.icapass); ca_box.addWidget(ca_show)
        form.addRow("CA password (blank if CA is unencrypted)", ca_row)
        self.ikeyprotect, self.ikeypass, self.ikeypassconfirm = self.add_new_password_controls(form, "FlexEdge private key")
        form.addRow("Automatic output folder", self.iout)
        note = QLabel("The output includes certificate.pem, private-key.pem, fullchain.pem, CA files, a validation report, and Windows/Linux trust scripts.")
        note.setWordWrap(True); form.addRow(note)
        form.addRow(self.primary_button("Issue complete FlexEdge HTTPS package", self.issue))
        return page

    def update_pki_workspace(self):
        parent, name = self.pkiparent.text().strip(), self.pkiname.text().strip()
        self.pkiworkspace.setText(str(Path(parent) / safe_name(name)) if parent and name else "")

    def infer_legacy_organization(self, workspace: str | Path) -> str:
        if not self.engine: return ""
        certificate = Project.legacy_files(workspace)["intermediate_certificate"]
        output = self.engine.run("x509", "-in", str(certificate), "-noout", "-subject", "-nameopt", "RFC2253")
        match = re.search(r"(?:^|,)O=([^,]+)", output.replace("subject=", ""))
        return match.group(1).replace("\\,", ",").strip() if match else ""

    def migrate_legacy_project(self, workspace: str | Path) -> Project | None:
        path = Path(workspace)
        answer = QMessageBox.question(
            self, "Legacy PKI detected",
            "This folder contains a complete PKI created by an earlier version.\n\n"
            "Migrate it to the new project format? Existing certificates and private keys will not be changed.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer != QMessageBox.Yes: return None
        suggested = self.infer_legacy_organization(path)
        organization, accepted = QInputDialog.getText(
            self, "Confirm organization", "Organization for this PKI project:", text=suggested)
        if not accepted: return None
        project = Project.migrate_legacy(path, organization)
        legacy = Project.legacy_files(path)
        create_trust_bundle(path / "trust-installers", legacy["root_certificate"], legacy["intermediate_certificate"])
        self.log.append(f"Migrated legacy PKI project without changing existing keys: {path}")
        return project

    def apply_project(self, project: Project):
        self.project = project
        project.create_structure()
        self.project_status.setText(f"Loaded: {project.project_name} — {project.organization}")
        self.project_status.setStyleSheet("font-weight: 600; color: #16a34a")
        with QSignalBlocker(self.iws): self.iws.setText(project.workspace)
        with QSignalBlocker(self.csrws): self.csrws.setText(project.workspace)
        self.csrorg.setText(project.organization); self.iorg.setText(project.organization)
        self.idns.setText(project.dns_suffix)
        if project.ca_key_encrypted is True:
            self.icapass.setPlaceholderText("Required: this project uses encrypted CA keys")
        elif project.ca_key_encrypted is False:
            self.icapass.setPlaceholderText("Not required: this project uses unencrypted CA keys")
        else:
            self.icapass.setPlaceholderText("Enter only if the CA key is encrypted")
        self.update_issue_defaults(); self.update_csr_defaults()

    def load_project(self, value):
        try:
            if Project.is_legacy_workspace(value):
                project = self.migrate_legacy_project(value)
                if project is None:
                    self.project_status.setText("Legacy PKI migration cancelled; no files were changed.")
                    self.project_status.setStyleSheet("color: #ca8a04"); return
            else:
                project = Project.load(value)
            self.apply_project(project)
        except Exception as exc:
            self.project = None; self.project_status.setText(str(exc)); self.project_status.setStyleSheet("color: #dc2626")

    def update_csr_defaults(self):
        if not self.project: return
        name = self.csrname.text().strip()
        if name:
            host = name if "." in name else f"{name}.{self.project.dns_suffix}"
            self.csrcn.setText(host.lower()); self.csrsans.setText(host.lower())
            self.csrout.setText(str(self.project.pending_folder(name)))

    def update_issue_defaults(self):
        if not self.project: return
        name = self.idevice.text().strip(); suffix = self.idns.text().strip().strip(".") or self.project.dns_suffix
        if not name: return
        host = name if "." in name else f"{name}.{suffix}"
        values = [host.lower()]
        ip = self.iip.text().strip()
        if ip:
            try: values.append(str(ipaddress.ip_address(ip)))
            except ValueError: pass
        values.extend(x.strip() for x in self.iextra.text().split(",") if x.strip())
        values = list(dict.fromkeys(values))
        self.icn.setText(host.lower()); self.isans.setText(", ".join(values)); self.iorg.setText(self.project.organization)
        self.iout.setText(str(self.project.device_folder(name)))

    def guard(self, action):
        if not self.engine:
            QMessageBox.critical(self, "OpenSSL required", "OpenSSL was not detected."); return
        try:
            result = action()
            if result: self.log.append("\nCreated:\n" + "\n".join(f"  {k}: {v}" for k, v in result.items()))
            QMessageBox.information(self, "Completed", "The operation completed successfully. Review the output folder and validation report.")
        except Exception as exc:
            self.log.append(f"ERROR: {exc}"); QMessageBox.critical(self, "Operation failed", str(exc))

    @staticmethod
    def sans(field): return [x.strip() for x in field.text().split(",") if x.strip()]

    def validate_import(self):
        self.guard(lambda: self.engine.package_existing(Path(self.icert.text()), Path(self.ikey.text()),
            Path(self.ica.text()), Path(self.iimportout.text()), self.ipass.text()))

    def create_csr(self):
        if not self.project: self.load_project(self.csrws.text())
        def work():
            password = self.chosen_password(self.csrprotect, self.csrpass, self.csrpassconfirm, "CSR")
            key, csr = self.engine.generate_csr(Path(self.csrout.text()), Subject(self.csrcn.text(), self.csrorg.text()), self.sans(self.csrsans), password)
            return {"private_key": key, "csr": csr}
        self.guard(work)

    def create_pki(self):
        def work():
            workspace = Path(self.pkiworkspace.text()); project = Project(str(workspace), self.pkiorg.text().strip(), self.pkiname.text().strip(), self.pkidns.text().strip() or "local")
            if not project.organization: raise ValueError("Organization is required.")
            if project.manifest.exists(): raise FileExistsError(f"Project already exists: {project.manifest}")
            password = self.chosen_password(self.pkiprotect, self.pkipass, self.pkipassconfirm, "CA", severe=True)
            project.ca_key_encrypted = bool(password)
            project.save()
            try:
                result = self.engine.create_pki(workspace, Subject(f"{project.organization} Industrial Root CA", project.organization), Subject(f"{project.organization} Industrial Device Issuing CA", project.organization), password)
            except Exception:
                project.manifest.unlink(missing_ok=True); raise
            self.load_project(workspace); return {"project": project.manifest, **result}
        self.guard(work)

    def issue(self):
        if not self.project: self.load_project(self.iws.text())
        def work():
            if not self.project: raise ValueError("Load a valid PKI project first.")
            if not self.iip.text().strip(): raise ValueError("Device IP address is required for the FlexEdge profile.")
            key_password = self.chosen_password(self.ikeyprotect, self.ikeypass, self.ikeypassconfirm, "FlexEdge")
            return self.engine.issue_server(self.project.path, Path(self.iout.text()), Subject(self.icn.text(), self.project.organization), self.sans(self.isans), self.icapass.text(), key_password)
        self.guard(work)


def main():
    app = QApplication(sys.argv); app.setStyle("Fusion"); window = MainWindow(); window.show(); return app.exec()


if __name__ == "__main__": raise SystemExit(main())
