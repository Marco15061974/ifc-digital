"""IFC Digital Premium V2 - Staging Server V4."""

import os
import sys
import hashlib
import base64

from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import server_staging_v3

server = server_staging_v3.server_staging_v2.server

UI_FILE = (
    Path(__file__).resolve().parent
    / "ifc_premium_v2_staging.html"
)

UI_PATH = "/premium"

UI_ORIGIN = "https://ifc-digital-staging.onrender.com"


def load_ui():
    body = UI_FILE.read_bytes()

    if not body or len(body) > 1024 * 1024:
        raise RuntimeError("Invalid staging UI file")

    return body


class Handler(server_staging_v3.Handler):
    """V3 API plus dedicated Premium Staging UI."""

    def serve_premium(self, head_only=False):
        try:
            body = load_ui()
        except (OSError, RuntimeError):
            return self.send_json(
                503,
                {
                    "status": "error",
                    "message": "Premium UI unavailable",
                },
            )

        script_start = body.find(b"<script>")
        script_end = body.find(b"</script>")

        if script_start < 0 or script_end <= script_start:
            return self.send_json(
                503,
                {
                    "status": "error",
                    "message": "Invalid Premium UI",
                },
            )

        script = body[script_start + 8:script_end]

        script_hash = base64.b64encode(
            hashlib.sha256(script).digest()
        ).decode("ascii")

        csp = (
            "default-src 'none'; "
            f"script-src 'sha256-{script_hash}'; "
            "style-src 'unsafe-inline'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "base-uri 'none'; "
            "form-action 'none'; "
            "frame-ancestors 'none'; "
            "object-src 'none'"
        )

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )

        self.send_header(
            "Content-Length",
            str(len(body)),
        )

        self.send_header(
            "Cache-Control",
            "no-store",
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff",
        )

        self.send_header(
            "X-Frame-Options",
            "DENY",
        )

        self.send_header(
            "Referrer-Policy",
            "no-referrer",
        )

        self.send_header(
            "Content-Security-Policy",
            csp,
        )

        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )

        self.end_headers()

        if not head_only:
            self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == UI_PATH:
            return self.serve_premium()

        return super().do_GET()

    def do_HEAD(self):
        path = urlsplit(self.path).path

        if path == UI_PATH:
            return self.serve_premium(head_only=True)

        self.send_response(405)
        self.send_header("Allow", "GET")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    if server.LEGACY_ENABLED:
        raise RuntimeError(
            "Legacy API token must be disabled for V4"
        )

    load_ui()

    server.authentication_service()
    server.initialize_database()

    port = int(os.environ.get("PORT", "8080"))

    print(
        "IFC Digital Staging V4 starting",
        flush=True,
    )

    print(
        f"Premium UI: {UI_ORIGIN}{UI_PATH}",
        flush=True,
    )

    ThreadingHTTPServer(
        ("0.0.0.0", port),
        Handler,
    ).serve_forever()


if __name__ == "__main__":
    main()
