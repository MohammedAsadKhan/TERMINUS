# File name: test_gui_setup_wizard.py
# Author: Team LARP
# Revision date: 2026-11-14
# Version: 0.1.0
# Purpose: Keep the optional GUI handoff on the supported local setup path.

"""The optional GUI must delegate configuration to the maintained CLI."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("tkinter")

spec = importlib.util.spec_from_file_location(
    "gui_setup_wizard", Path(__file__).parents[1] / "scripts/gui_setup_wizard.py"
)
wizard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wizard)


def test_gui_setup_requires_source_folder_and_locked_cli(tmp_path, monkeypatch):
    with pytest.raises(FileNotFoundError, match="incomplete"):
        wizard.setup_command(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (tmp_path / "run_service.bat").write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr(wizard.shutil, "which", lambda name: "C:/uv.exe")
    assert wizard.setup_command(tmp_path) == [
        "C:/uv.exe", "run", "--frozen", "terminus-setup"
    ]
    monkeypatch.setattr(wizard.shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError, match="Install uv"):
        wizard.setup_command(tmp_path)


def test_packaged_gui_finds_source_parent(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (tmp_path / "run_service.bat").write_text("@echo off\n", encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    monkeypatch.chdir(dist)
    monkeypatch.setattr(wizard.sys, "argv", [str(dist / "TerminusSetupWizard.exe")])
    assert wizard.project_root() == tmp_path
