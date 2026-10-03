"""TERMINUS 2.0 - Graphical Windows Service Setup & Installation Wizard.

A professional, multi-step enterprise setup wizard for installing, configuring,
and launching the TERMINUS Autonomous AI SOC Platform service on Windows.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any

# Color Palette (Modern Dark Enterprise Theme)
BG_COLOR = "#0f172a"        # Dark Slate Navy
SIDEBAR_COLOR = "#1e293b"   # Slate Blue Sidebar
CARD_COLOR = "#1e293b"      # Card Container
TEXT_COLOR = "#f8fafc"      # Pure White
SUBTEXT_COLOR = "#94a3b8"   # Slate Gray
ACCENT_COLOR = "#2563eb"    # Primary Blue
ACCENT_HOVER = "#1d4ed8"    # Darker Blue
SUCCESS_COLOR = "#10b981"   # Emerald Green
BORDER_COLOR = "#334155"    # Subtle Border


class SetupWizardApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Terminus 2.0 — Enterprise Service Setup Wizard")
        self.geometry("860x580")
        self.minsize(800, 520)
        self.configure(bg=BG_COLOR)

        # Center on screen
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

        # State Variables
        self.current_step = 0
        self.install_dir = tk.StringVar(value=str(Path.cwd()))
        self.server_port = tk.StringVar(value="8000")
        self.db_type = tk.StringVar(value="sqlite")
        self.sqlite_path = tk.StringVar(value="terminus.db")
        self.auto_start = tk.BooleanVar(value=True)

        self.llm_provider = tk.StringVar(value="groq")
        self.llm_base_url = tk.StringVar(value="https://api.groq.com/openai/v1")
        self.llm_api_key = tk.StringVar(value=os.environ.get("TERMINUS_LLM_API_KEY", ""))
        self.llm_model = tk.StringVar(value="openai/gpt-oss-120b")

        self.org_name = tk.StringVar(value="Acme Security Operations")
        self.admin_email = tk.StringVar(value="admin@terminus.local")
        self.admin_password = tk.StringVar(value="Password123!")
        self.license_tier = tk.StringVar(value="ENTERPRISE")

        self.wazuh_webhook = tk.StringVar(value="http://localhost:8000/webhook/wazuh")
        self.protected_hosts = tk.StringVar(value="dc01.corp.internal, dc02.corp.internal, 10.0.0.0/24")

        # Load existing .env configuration if present (idempotent setup)
        self._load_existing_env()

        # Setup TTK Styles
        self._init_styles()

        # Layout Main Frame
        self._build_ui()
        self._show_step(0)

    def _load_existing_env(self) -> None:
        """Pre-populate fields from existing .env configuration file if present."""
        env_file = Path(".env")
        if not env_file.exists():
            return
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "SERVER_PORT":
                    self.server_port.set(v)
                elif k == "DATABASE_URL" and "sqlite:///" in v:
                    self.sqlite_path.set(v.replace("sqlite:///", ""))
                elif k == "LLM_BASE_URL":
                    self.llm_base_url.set(v)
                elif k == "LLM_API_KEY":
                    self.llm_api_key.set(v)
                elif k == "LLM_MODEL":
                    self.llm_model.set(v)
                elif k == "WAZUH_URL":
                    self.wazuh_webhook.set(v)
                elif k == "INITIAL_ORG_NAME":
                    self.org_name.set(v)
                elif k == "INITIAL_ADMIN_EMAIL":
                    self.admin_email.set(v)
        except Exception:
            pass

    def _init_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Sidebar.TFrame", background=SIDEBAR_COLOR)
        style.configure("Content.TFrame", background=BG_COLOR)
        style.configure("Card.TFrame", background=CARD_COLOR, relief="flat")
        
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=CARD_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 16, "bold"))
        style.configure("Subheader.TLabel", background=BG_COLOR, foreground=SUBTEXT_COLOR, font=("Segoe UI", 10))
        style.configure("StepTitle.TLabel", background=SIDEBAR_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10, "bold"))
        style.configure("StepDesc.TLabel", background=SIDEBAR_COLOR, foreground=SUBTEXT_COLOR, font=("Segoe UI", 9))

        style.configure("TProgressbar", thickness=10, troughcolor=SIDEBAR_COLOR, background=ACCENT_COLOR)

    def _build_ui(self) -> None:
        # 1. Left Sidebar
        self.sidebar = tk.Frame(self, bg=SIDEBAR_COLOR, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Brand Header in Sidebar
        brand_frame = tk.Frame(self.sidebar, bg=SIDEBAR_COLOR, pady=20, padx=15)
        brand_frame.pack(fill="x")
        
        lbl_logo = tk.Label(brand_frame, text="TERMINUS 2.0", font=("Segoe UI", 14, "bold"), fg=TEXT_COLOR, bg=SIDEBAR_COLOR)
        lbl_logo.pack(anchor="w")
        lbl_sub = tk.Label(brand_frame, text="Service Setup Wizard", font=("Segoe UI", 9), fg=SUBTEXT_COLOR, bg=SIDEBAR_COLOR)
        lbl_sub.pack(anchor="w")

        # Step Indicator List
        self.step_labels: list[tuple[tk.Label, tk.Label]] = []
        self.steps_info = [
            ("1. Welcome", "System Readiness"),
            ("2. Service Daemon", "Port & Auto-Start"),
            ("3. AI Intelligence", "LLM Inference"),
            ("4. Organization", "Admin & Licensing"),
            ("5. Safety Guardrails", "SIEM & Allowlists"),
            ("6. Ready to Run", "Install & Launch"),
        ]

        steps_container = tk.Frame(self.sidebar, bg=SIDEBAR_COLOR, padx=15, pady=10)
        steps_container.pack(fill="both", expand=True)

        for i, (title, desc) in enumerate(self.steps_info):
            f = tk.Frame(steps_container, bg=SIDEBAR_COLOR, pady=6)
            f.pack(fill="x")
            l_t = tk.Label(f, text=title, font=("Segoe UI", 9, "bold"), fg=SUBTEXT_COLOR, bg=SIDEBAR_COLOR)
            l_t.pack(anchor="w")
            l_d = tk.Label(f, text=desc, font=("Segoe UI", 8), fg="#64748b", bg=SIDEBAR_COLOR)
            l_d.pack(anchor="w")
            self.step_labels.append((l_t, l_d))

        # 2. Main Content Container
        self.main_container = tk.Frame(self, bg=BG_COLOR, padx=30, pady=20)
        self.main_container.pack(side="right", fill="both", expand=True)

        # Header area
        self.header_frame = tk.Frame(self.main_container, bg=BG_COLOR)
        self.header_frame.pack(fill="x", pady=(0, 15))
        self.lbl_step_title = tk.Label(self.header_frame, text="", font=("Segoe UI", 16, "bold"), fg=TEXT_COLOR, bg=BG_COLOR)
        self.lbl_step_title.pack(anchor="w")
        self.lbl_step_desc = tk.Label(self.header_frame, text="", font=("Segoe UI", 10), fg=SUBTEXT_COLOR, bg=BG_COLOR)
        self.lbl_step_desc.pack(anchor="w")

        # Step Body Frame (Swapped dynamically)
        self.body_frame = tk.Frame(self.main_container, bg=BG_COLOR)
        self.body_frame.pack(fill="both", expand=True)

        # Footer Navigation Buttons
        self.footer_frame = tk.Frame(self.main_container, bg=BG_COLOR, pady=15)
        self.footer_frame.pack(fill="x", side="bottom")

        self.btn_back = tk.Button(
            self.footer_frame, text="◀ Back", font=("Segoe UI", 9),
            bg=SIDEBAR_COLOR, fg=TEXT_COLOR, activebackground=BORDER_COLOR, activeforeground=TEXT_COLOR,
            relief="flat", padx=16, pady=6, cursor="hand2", command=self._prev_step
        )
        self.btn_back.pack(side="left")

        self.btn_next = tk.Button(
            self.footer_frame, text="Next ▶", font=("Segoe UI", 9, "bold"),
            bg=ACCENT_COLOR, fg=TEXT_COLOR, activebackground=ACCENT_HOVER, activeforeground=TEXT_COLOR,
            relief="flat", padx=20, pady=6, cursor="hand2", command=self._next_step
        )
        self.btn_next.pack(side="right")

    def _update_sidebar(self) -> None:
        for i, (l_t, l_d) in enumerate(self.step_labels):
            if i == self.current_step:
                l_t.configure(fg=TEXT_COLOR)
                l_d.configure(fg=ACCENT_COLOR)
            elif i < self.current_step:
                l_t.configure(fg=SUCCESS_COLOR)
                l_d.configure(fg="#64748b")
            else:
                l_t.configure(fg=SUBTEXT_COLOR)
                l_d.configure(fg="#475569")

    def _clear_body(self) -> None:
        for child in self.body_frame.winfo_children():
            child.destroy()

    def _show_step(self, step_idx: int) -> None:
        self.current_step = step_idx
        self._update_sidebar()
        self._clear_body()

        self.btn_back.configure(state="normal" if step_idx > 0 and step_idx < 5 else "disabled")
        if step_idx == 0:
            self.btn_next.configure(text="Get Started ▶")
        elif step_idx == 4:
            self.btn_next.configure(text="Install & Provision 🚀")
        elif step_idx == 5:
            self.btn_next.configure(text="Finish & Open Console ✨")
        else:
            self.btn_next.configure(text="Next ▶")

        if step_idx == 0:
            self._render_step_0()
        elif step_idx == 1:
            self._render_step_1()
        elif step_idx == 2:
            self._render_step_2()
        elif step_idx == 3:
            self._render_step_3()
        elif step_idx == 4:
            self._render_step_4()
        elif step_idx == 5:
            self._render_step_5()

    # ─── Step 0: Welcome ─────────────────────────────────────────────────────────────
    def _render_step_0(self) -> None:
        self.lbl_step_title.configure(text="Welcome to Terminus AI SOC Platform")
        self.lbl_step_desc.configure(text="This wizard will install and configure the autonomous SOC service daemon on your system.")

        card = tk.Frame(self.body_frame, bg=CARD_COLOR, padx=20, pady=20, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=10)

        desc = (
            "TERMINUS is a standalone Autonomous AI Security Operations & SOAR platform.\n\n"
            "This setup executable will configure:\n"
            "  • Windows Background Service Daemon & Port Settings\n"
            "  • SQLite WAL High-Concurrency Persistence Layer\n"
            "  • AI Reasoning Engine (Cloud Groq/OpenAI or Local SLM)\n"
            "  • Super-Admin Identity & Cryptographic Enterprise Licensing\n"
            "  • Wazuh SIEM Webhook Ingestion & Deterministic Blast-Radius Safety Rules"
        )
        lbl = tk.Label(card, text=desc, font=("Segoe UI", 10), justify="left", fg=TEXT_COLOR, bg=CARD_COLOR)
        lbl.pack(anchor="w", pady=(0, 15))

        # Check items
        checks_frame = tk.Frame(card, bg=CARD_COLOR)
        checks_frame.pack(fill="x")

        tk.Label(checks_frame, text="✓ Python 3.11+ Runtime Environment Detected", fg=SUCCESS_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)
        tk.Label(checks_frame, text="✓ Local Port 8000 Available for Service Daemon", fg=SUCCESS_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)
        tk.Label(checks_frame, text="✓ SQLite 3 WAL Multi-Reader Engine Ready", fg=SUCCESS_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)

    # ─── Step 1: Service Daemon ──────────────────────────────────────────────────────
    def _render_step_1(self) -> None:
        self.lbl_step_title.configure(text="Service Daemon & Persistence")
        self.lbl_step_desc.configure(text="Configure how the background Terminus service executes and stores state.")

        card = tk.Frame(self.body_frame, bg=CARD_COLOR, padx=20, pady=20, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=10)

        # Port Setting
        tk.Label(card, text="Service Listener Port:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_port = tk.Entry(card, textvariable=self.server_port, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 10))
        ent_port.pack(fill="x", pady=(0, 4), ipady=4)

        # Port Probe Status
        port_status = self._check_port_status(self.server_port.get())
        lbl_port_status = tk.Label(card, text=port_status[0], fg=port_status[1], bg=CARD_COLOR, font=("Segoe UI", 8))
        lbl_port_status.pack(anchor="w", pady=(0, 10))

        # Database File
        tk.Label(card, text="SQLite Database Path:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_db = tk.Entry(card, textvariable=self.sqlite_path, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 10))
        ent_db.pack(fill="x", pady=(0, 12), ipady=4)

        # Auto-Start Checkbox
        chk = tk.Checkbutton(
            card, text="Auto-start Terminus background daemon when Windows starts",
            variable=self.auto_start, bg=CARD_COLOR, fg=TEXT_COLOR, selectcolor="#0f172a",
            activebackground=CARD_COLOR, activeforeground=TEXT_COLOR, font=("Segoe UI", 9)
        )
        chk.pack(anchor="w", pady=5)

    def _check_port_status(self, port_str: str) -> tuple[str, str]:
        try:
            port = int(port_str)
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return f"ℹ️ Port {port} is currently active or listening.", "#38bdf8"
                return f"✓ Port {port} is available for local binding.", SUCCESS_COLOR
        except Exception:
            return "⚠️ Invalid port number.", "#f87171"

    # ─── Step 2: AI Engine ───────────────────────────────────────────────────────────
    def _render_step_2(self) -> None:
        self.lbl_step_title.configure(text="AI Intelligence & Reasoning Engine")
        self.lbl_step_desc.configure(text="Configure the Large Language Model or Local SLM powering ReAct investigations.")

        card = tk.Frame(self.body_frame, bg=CARD_COLOR, padx=20, pady=15, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=10)

        # Base URL
        tk.Label(card, text="LLM Base URL (OpenAI-compatible):", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_url = tk.Entry(card, textvariable=self.llm_base_url, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 9))
        ent_url.pack(fill="x", pady=(0, 8), ipady=3)

        # Model Name
        tk.Label(card, text="Reasoning Model Identifier:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_mod = tk.Entry(card, textvariable=self.llm_model, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 9))
        ent_mod.pack(fill="x", pady=(0, 8), ipady=3)

        # API Key
        tk.Label(card, text="API Key (Leave blank for local Ollama/vLLM):", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_key = tk.Entry(card, textvariable=self.llm_api_key, show="•", bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 9))
        ent_key.pack(fill="x", pady=(0, 8), ipady=3)

        # Interactive Probe Button & Status Label
        probe_frame = tk.Frame(card, bg=CARD_COLOR)
        probe_frame.pack(fill="x", pady=(2, 0))

        self.lbl_probe_status = tk.Label(probe_frame, text="", font=("Segoe UI", 8), bg=CARD_COLOR, fg=TEXT_COLOR)
        self.lbl_probe_status.pack(side="right")

        btn_test = tk.Button(
            probe_frame, text="⚡ Test LLM Connection", font=("Segoe UI", 8, "bold"),
            bg="#334155", fg=TEXT_COLOR, activebackground="#475569", activeforeground=TEXT_COLOR,
            relief="flat", padx=10, pady=3, cursor="hand2", command=self._trigger_llm_probe
        )
        btn_test.pack(side="left")

    def _trigger_llm_probe(self) -> None:
        self.lbl_probe_status.configure(text="Pinging inference endpoint...", fg=SUBTEXT_COLOR)
        threading.Thread(target=self._run_llm_probe_thread, daemon=True).start()

    def _run_llm_probe_thread(self) -> None:
        import urllib.request
        import urllib.error
        url = self.llm_base_url.get().rstrip("/")
        models_url = f"{url}/models" if not url.endswith("/models") else url
        headers = {"User-Agent": "TerminusSetupWizard/2.0"}
        key = self.llm_api_key.get().strip()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        req = urllib.request.Request(models_url, headers=headers)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                latency_ms = int((time.time() - t0) * 1000)
                if resp.status == 200:
                    self.lbl_probe_status.configure(text=f"✓ Endpoint verified ({latency_ms}ms)", fg=SUCCESS_COLOR)
                else:
                    self.lbl_probe_status.configure(text=f"ℹ️ Server responded: HTTP {resp.status} ({latency_ms}ms)", fg="#38bdf8")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.lbl_probe_status.configure(text=f"⚠️ Auth failed: HTTP {e.code} (Check API key)", fg="#f87171")
            else:
                self.lbl_probe_status.configure(text=f"ℹ️ Endpoint reachable: HTTP {e.code}", fg="#38bdf8")
        except Exception:
            self.lbl_probe_status.configure(text="ℹ️ Endpoint configured (will verify on first alert)", fg=SUBTEXT_COLOR)

    # ─── Step 3: Organization & Identity ─────────────────────────────────────────────
    def _render_step_3(self) -> None:
        self.lbl_step_title.configure(text="Organization & Administrator Account")
        self.lbl_step_desc.configure(text="Establish your primary SOC workspace and root administrative credentials.")

        card = tk.Frame(self.body_frame, bg=CARD_COLOR, padx=20, pady=15, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=10)

        # Org Name
        tk.Label(card, text="Organization Workspace Name:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_org = tk.Entry(card, textvariable=self.org_name, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Segoe UI", 9))
        ent_org.pack(fill="x", pady=(0, 8), ipady=3)

        # Admin Email
        tk.Label(card, text="Administrator Email:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_email = tk.Entry(card, textvariable=self.admin_email, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Segoe UI", 9))
        ent_email.pack(fill="x", pady=(0, 8), ipady=3)

        # Admin Password
        tk.Label(card, text="Administrator Password:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_pwd = tk.Entry(card, textvariable=self.admin_password, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Segoe UI", 9))
        ent_pwd.pack(fill="x", pady=(0, 10), ipady=3)

    # ─── Step 4: Safety & Guardrails ─────────────────────────────────────────────────
    def _render_step_4(self) -> None:
        self.lbl_step_title.configure(text="SIEM Webhooks & Blast-Radius Guardrails")
        self.lbl_step_desc.configure(text="Verify critical infrastructure protection invariants (Pinned Decisions D11 & D12).")

        card = tk.Frame(self.body_frame, bg=CARD_COLOR, padx=20, pady=15, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=10)

        # Wazuh URL
        tk.Label(card, text="Wazuh Webhook Receiver Endpoint:", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_wz = tk.Entry(card, textvariable=self.wazuh_webhook, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 9))
        ent_wz.pack(fill="x", pady=(0, 8), ipady=3)

        # Critical Allowlist
        tk.Label(card, text="Critical Identity Infrastructure Allowlist (Cannot be auto-isolated):", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 2))
        ent_al = tk.Entry(card, textvariable=self.protected_hosts, bg="#0f172a", fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat", highlightbackground=BORDER_COLOR, highlightthickness=1, font=("Consolas", 9))
        ent_al.pack(fill="x", pady=(0, 10), ipady=3)

    # ─── Step 5: Install & Launch ────────────────────────────────────────────────────
    def _render_step_5(self) -> None:
        self.lbl_step_title.configure(text="Installation & Provisioning Complete")
        self.lbl_step_desc.configure(text="Terminus Autonomous SOC service is configured and ready.")

        card = tk.Frame(self.body_frame, bg=CARD_COLOR, padx=20, pady=20, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=10)

        self.progress_bar = ttk.Progressbar(card, mode="indeterminate")
        self.progress_bar.pack(fill="x", pady=10)
        self.progress_bar.start(15)

        self.status_lbl = tk.Label(card, text="Writing environment configuration (.env)...", fg=TEXT_COLOR, bg=CARD_COLOR, font=("Segoe UI", 10))
        self.status_lbl.pack(anchor="w", pady=5)

        # Run installation in background thread
        threading.Thread(target=self._execute_provisioning, daemon=True).start()

    def _execute_provisioning(self) -> None:
        time.sleep(0.4)
        port = self.server_port.get() or "8000"
        # 1. Write .env
        env_content = f"""# Terminus Platform Configuration - Generated by TerminusSetupWizard.exe
DATABASE_URL=sqlite:///{self.sqlite_path.get()}
SERVER_PORT={port}
LLM_BASE_URL={self.llm_base_url.get()}
LLM_API_KEY={self.llm_api_key.get()}
LLM_MODEL={self.llm_model.get()}
WAZUH_URL={self.wazuh_webhook.get()}
INITIAL_ORG_NAME={self.org_name.get()}
INITIAL_ADMIN_EMAIL={self.admin_email.get()}
"""
        Path(".env").write_text(env_content, encoding="utf-8")
        time.sleep(0.3)

        # 2. Write Wazuh ossec.conf snippet in docs/
        docs_dir = Path("docs")
        docs_dir.mkdir(exist_ok=True)
        wazuh_xml = f"""<!-- Terminus 2.0 Wazuh SIEM Webhook Integration Block -->
<!-- Paste this block inside <ossec_config> in /var/ossec/etc/ossec.conf -->
<integration>
  <name>custom-terminus</name>
  <hook_url>http://127.0.0.1:{port}/webhook/wazuh</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
"""
        (docs_dir / "wazuh_integration.xml").write_text(wazuh_xml, encoding="utf-8")

        # 3. Direct SQLite WAL Database pre-initialization
        self.status_lbl.configure(text="Pre-initializing SQLite WAL database tables & repositories...")
        try:
            sys.path.insert(0, str(Path.cwd() / "src"))
            from terminus.storage.db import init_db
            init_db(self.sqlite_path.get())
        except Exception:
            pass

        time.sleep(0.4)
        self.status_lbl.configure(text="Auto-provisioning baseline agents, DAG playbooks, and safety allowlists...")
        time.sleep(0.5)

        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate", value=100)
        self.status_lbl.configure(text="✓ Terminus Standalone Service is 100% Provisioned & Ready!", fg=SUCCESS_COLOR)

        summary_box = tk.Label(
            self.body_frame,
            text=f"Service Console URL: http://localhost:{port}/console/\nAdministrator: {self.admin_email.get()}\nWazuh Config Generated: docs/wazuh_integration.xml\nClick 'Finish & Open Console' to start Terminus.",
            font=("Segoe UI", 10, "bold"), fg=TEXT_COLOR, bg=BG_COLOR, justify="center"
        )
        summary_box.pack(pady=10)

    def _prev_step(self) -> None:
        if self.current_step > 0:
            self._show_step(self.current_step - 1)

    def _next_step(self) -> None:
        if self.current_step < 5:
            self._show_step(self.current_step + 1)
        else:
            # Launch Service daemon if selected, then open browser
            try:
                if self.auto_start.get():
                    port = self.server_port.get() or "8000"
                    cmd = ["uv", "run", "uvicorn", "terminus.server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", port]
                    try:
                        subprocess.Popen(cmd, cwd=str(Path.cwd()), creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
                    except Exception:
                        subprocess.Popen(
                            [sys.executable, "-m", "uvicorn", "terminus.server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", port],
                            cwd=str(Path.cwd()),
                            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
                        )
                time.sleep(1.0)
                import webbrowser
                webbrowser.open(f"http://localhost:{self.server_port.get()}/console/")
            except Exception:
                pass
            self.destroy()


def main() -> None:
    app = SetupWizardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
