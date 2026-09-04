"""Terminus Opposer Standalone Server.

Runs independently on port 8080 to host the Opposer Red Team Dashboard.
Does not import or touch any product code in terminus.
"""

from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys


class OpposerHandler(SimpleHTTPRequestHandler):
    """Serve the opposer dashboard static interface."""

    def __init__(self, *args, **kwargs):
        directory = str(Path(__file__).parent)
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        if self.path in ("/", "/opposer", "/index.html"):
            self.path = "/index.html"
        return super().do_GET()


def main():
    port = 8080
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, OpposerHandler)
    print(f"[+] Terminus Opposer Standalone Suite listening at http://localhost:{port}")
    print(f"[+] Point your target URL to your Ngrok tunnel or honeypot endpoint.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Opposer service stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
