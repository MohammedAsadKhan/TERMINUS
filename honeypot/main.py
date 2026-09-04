"""Lightweight Native Python Honeypot Target Service.

Runs natively on Windows/Linux on port 5000 with ZERO dependencies.
Listens for real incoming HTTP traffic (from Opposer, browser, or Ngrok),
detects threat vectors in real time, and sends actual SIEM alerts to Terminus (port 8000).
"""

from __future__ import annotations

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import re
import sys
import time
import urllib.request

AGENT_SOC_WEBHOOK = "http://localhost:8000/wazuh"
ORG_ID = "org-00000001"
SESSION_TOKEN = "tok-demo-sim-agent"

PATTERNS = [
    {
        "name": "Log4Shell RCE Attempt",
        "pattern": r"\$\{jndi:(ldap|rmi|dns)://",
        "rule_id": 100201,
        "level": 12,
        "mitre": "T1190"
    },
    {
        "name": "Spring4Shell ClassLoader Exploit",
        "pattern": r"class\.module\.classLoader",
        "rule_id": 100205,
        "level": 11,
        "mitre": "T1505.003"
    },
    {
        "name": "Directory Traversal Attempt",
        "pattern": r"(\.\./\.\./|/etc/passwd|c:\\windows\\system32)",
        "rule_id": 100300,
        "level": 8,
        "mitre": "T1083"
    },
    {
        "name": "SQL Injection Pattern",
        "pattern": r"(UNION\s+SELECT|SELECT\s+.*\s+FROM|' OR '1'='1)",
        "rule_id": 100400,
        "level": 9,
        "mitre": "T1190"
    },
    {
        "name": "WebShell Execution Header",
        "pattern": r"(cmd\.exe|/bin/sh|/bin/bash|vssadmin|rundll32)",
        "rule_id": 100500,
        "level": 10,
        "mitre": "T1059"
    }
]


class HoneypotHandler(BaseHTTPRequestHandler):
    """HTTP request handler representing a vulnerable target web service."""

    def log_message(self, format, *args):
        """Custom clean logging output."""
        sys.stdout.write(f"[HONEYPOT :5000] {self.address_string()} - {args[0]}\n")

    def add_cors_headers(self):
        """Add Cross-Origin Resource Sharing headers for browser compatibility."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def inspect_and_alert(self, body_bytes: bytes = b""):
        """Inspect request headers, path, and body for threat signatures."""
        full_raw = f"{self.command} {self.path}\n"
        for k, v in self.headers.items():
            full_raw += f"{k}: {v}\n"
        full_raw += body_bytes.decode("utf-8", errors="ignore")

        detected_threat = None
        for p in PATTERNS:
            if re.search(p["pattern"], full_raw, re.IGNORECASE):
                detected_threat = p
                break

        if not detected_threat:
            detected_threat = {
                "name": "Unusual Web Access Anomaly",
                "pattern": "Generic",
                "rule_id": 100100,
                "level": 6,
                "mitre": "T1071.001"
            }

        alert_payload = {
            "id": f"alt-honeypot-{int(time.time() * 1000)}",
            "rule": {
                "id": detected_threat["rule_id"],
                "level": detected_threat["level"],
                "description": f"Honeypot Triggered: {detected_threat['name']} from {self.client_address[0]}",
                "mitre": {"id": detected_threat["mitre"]}
            },
            "agent": {
                "id": "agent-native-honeypot-01",
                "name": "prod-honeypot-5000"
            },
            "full_log": full_raw[:500],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        self.send_to_terminus(alert_payload)

    def send_to_terminus(self, payload: dict):
        """Forward detected threat alert to Terminus engine."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            AGENT_SOC_WEBHOOK,
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-Org-ID": ORG_ID,
                "Authorization": f"Bearer {SESSION_TOKEN}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                print(f"[HONEYPOT -> TERMINUS] Alert {payload['id']} sent successfully ({resp.status} OK)")
        except Exception as err:
            print(f"[HONEYPOT WARNING] Could not forward to Terminus: {err}")

    def do_OPTIONS(self):
        """Handle CORS preflight requests from Opposer browser client."""
        self.send_response(200)
        self.add_cors_headers()
        self.end_headers()

    def do_GET(self):
        self.inspect_and_alert()
        self.send_response(200)
        self.add_cors_headers()
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Vulnerable Web Application Target</h1><p>Active Honeypot Monitored by Terminus</p></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self.inspect_and_alert(body)
        self.send_response(200)
        self.add_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "received", "honeypot": "active"}')


def main():
    port = 5000
    server = HTTPServer(("0.0.0.0", port), HoneypotHandler)
    print("==================================================================")
    print(f"[+] REAL LIGHTWEIGHT HONEYPOT SERVICE RUNNING ON PORT {port}")
    print(f"[+] Target URL for Ngrok / Opposer: http://localhost:{port}")
    print(f"[+] Forwards Real Detected Threats To: {AGENT_SOC_WEBHOOK}")
    print("==================================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Honeypot stopped.")


if __name__ == "__main__":
    main()
