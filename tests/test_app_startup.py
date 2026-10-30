# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import app


def test_opcua_host_uses_explicit_primary_dns() -> None:
    assert (
        app.opcua_host("ethersloth4", "ethersloth4.duckdns.org", "duckdns.org")
        == "ethersloth4.duckdns.org"
    )


def test_opcua_host_falls_back_to_project_suffix() -> None:
    assert app.opcua_host("red-08-b8-68", "", "duckdns.org") == "red-08-b8-68.duckdns.org"
    assert app.opcua_host("device.lab.example", "", "duckdns.org") == "device.lab.example"


class FakeSettings:
    def __init__(self, workspace: Path):
        self.workspace = workspace

    def value(self, key: str, default: str, type: type[str]) -> str:
        assert key == "project/last_workspace"
        assert default == ""
        assert type is str
        return str(self.workspace)


class FakeStatus:
    def setText(self, text: str) -> None:
        raise AssertionError(f"Unexpected status update: {text}")

    def setStyleSheet(self, style: str) -> None:
        raise AssertionError(f"Unexpected style update: {style}")


class FakeWindow:
    def __init__(self, workspace: Path):
        self.settings = FakeSettings(workspace)
        self.project_status = FakeStatus()
        self.loaded: list[str] = []

    def load_project(self, workspace: str) -> None:
        self.loaded.append(workspace)


def test_restore_last_project_loads_after_confirmation(tmp_path: Path, monkeypatch) -> None:
    window = FakeWindow(tmp_path)
    monkeypatch.setattr(
        app.QMessageBox,
        "question",
        lambda *args, **kwargs: app.QMessageBox.Yes,
    )

    app.MainWindow.restore_last_project(window)

    assert window.loaded == [str(tmp_path)]


def test_restore_last_project_does_not_load_after_rejection(tmp_path: Path, monkeypatch) -> None:
    window = FakeWindow(tmp_path)
    monkeypatch.setattr(
        app.QMessageBox,
        "question",
        lambda *args, **kwargs: app.QMessageBox.No,
    )

    app.MainWindow.restore_last_project(window)

    assert window.loaded == []
