# File name: test_presentation_network.py
# Author: Team LARP
# Revision date: 2026-11-14
# Version: 0.1.0
# Purpose: Keep synthetic presentation requests on an explicit loopback origin.

"""Presentation traffic must not forward its session token by redirect."""

import importlib.util
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "presentation_flood", Path(__file__).parents[1] / "scripts/live_interactive_flood.py"
)
flood = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flood)


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/terminus",
        "http://example.com:8000",
        "http://127.0.0.1:8000@other.example",
        "http://127.0.0.1:8000/other",
        "http://127.0.0.1",
        "http://127.0.0.1:99999",
    ],
)
def test_presentation_rejects_non_origin_or_non_loopback_urls(url):
    with pytest.raises(ValueError, match=r"Demo URL|Invalid demo URL"):
        flood.loopback_origin(url)


def test_presentation_redirect_cannot_forward_session_token():
    forwarded = []

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self):
            forwarded.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{destination.server_port}/landing"
            )
            self.end_headers()

        def log_message(self, *args):
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (destination, redirect)
    ]
    try:
        for thread in threads:
            thread.start()
        code, _ = flood.http_req(
            f"http://127.0.0.1:{redirect.server_port}",
            "GET",
            "/redirect",
            headers={"Authorization": "Bearer disposable-test-token"},
        )
        assert code == 302
        assert not forwarded
    finally:
        for server in (destination, redirect):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_presentation_alert_is_marked_synthetic_before_intake():
    received = []

    class Intake(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Intake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        thread.start()
        code, _ = flood.http_req(
            f"http://127.0.0.1:{server.server_port}",
            "POST",
            "/wazuh",
            {"id": "demo-1", "description": "SSH failures", "full_log": "test"},
        )
        assert code == 200
        assert received == [{
            "id": "demo-1",
            "description": "[SYNTHETIC] SSH failures",
            "full_log": "[SYNTHETIC] test",
        }]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_stream_refuses_direct_launch_outside_isolated_demo(monkeypatch):
    monkeypatch.delenv("TERMINUS_BANK_DEMO_MODE", raising=False)
    with pytest.raises(ValueError, match="isolated bank demo launcher"):
        asyncio.run(flood.run_simulation())
