# File name: gui_setup_wizard.py
# Author: Team LARP
# Revision date: 2026-11-14
# Version: 0.1.0
# Purpose: Open the supported local setup flow from a small Windows GUI.

"""Launch supported TERMINUS local setup without a parallel configuration path.

The former GUI wrote unsupported environment names, overwrote a maintained
Wazuh example, and launched the API on all interfaces. Keep one configuration
authority in ``terminus.setup`` and leave service startup to the manual.
"""

# ruff: noqa: INP001 -- this optional Windows entry point is a standalone script
from __future__ import annotations

import shutil
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox


def project_root() -> Path:
    """Find the extracted source folder from the launch location or executable."""
    launch_dir = Path(sys.argv[0]).resolve().parent
    for candidate in (Path.cwd(), Path.cwd().parent, launch_dir, launch_dir.parent):
        if (candidate / "pyproject.toml").is_file() and (
            candidate / "run_service.bat"
        ).is_file():
            return candidate
    raise FileNotFoundError(
        "Open this launcher from the extracted TERMINUS source folder."
    )


def setup_command(root: Path) -> list[str]:
    """Require the source tree and the same locked setup command as the manual."""
    if not (root / "pyproject.toml").is_file() or not (
        root / "run_service.bat"
    ).is_file():
        raise FileNotFoundError("The TERMINUS source folder is incomplete.")
    uv = shutil.which("uv")
    if uv is None:
        raise FileNotFoundError("Install uv and reopen this launcher.")
    return [uv, "run", "--frozen", "terminus-setup"]


def main() -> None:
    """Present an explicit handoff to the maintained setup command."""
    app = tk.Tk()
    app.title("TERMINUS local setup")
    app.geometry("500x230")
    app.resizable(width=False, height=False)
    tk.Label(
        app,
        text="TERMINUS local setup",
        font=("Segoe UI", 16, "bold"),
        pady=16,
    ).pack()
    tk.Label(
        app,
        text=(
            "The supported setup opens in a terminal. It configures the local "
            "SQLite service and optional connections. It does not deploy "
            "Wazuh or start response workers."
        ),
        font=("Segoe UI", 10),
        wraplength=450,
        justify="left",
    ).pack(padx=20)

    def launch() -> None:
        try:
            root = project_root()
            command = setup_command(root)
            # The operator needs to see the prompts and any setup error.
            _ = subprocess.Popen(  # noqa: S603 -- fixed CLI arguments; no shell
                command,
                cwd=root,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
        except (FileNotFoundError, OSError) as exc:
            _ = messagebox.showerror("TERMINUS setup", str(exc), parent=app)

    tk.Button(app, text="Open supported setup", command=launch, padx=14, pady=6).pack(
        pady=15
    )
    tk.Label(
        app,
        text="After setup, follow docs/INSTALLATION.md to start the loopback API.",
        font=("Segoe UI", 9),
    ).pack()
    app.mainloop()


if __name__ == "__main__":
    main()
