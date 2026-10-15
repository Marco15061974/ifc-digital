"""IFC Digital staging API. NOT for production deployment.

Personal sessions are supported for selected endpoints. Legacy shared-token
access is opt-in for development only. Rate limiting, revocation, HTTPS,
project ownership and full HTTP integration tests are still required.
"""
import hmac
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import psycopg
from psycopg.types.json import Jsonb
from auth_service import AuthenticationError, AuthenticationService

logging.basicConfig(level=logging.INFO)
DATABASE_URL = os.environ.get("DATABASE_URL")
MAX_BODY_BYTES = 1024 * 1024
API_TOKEN = os.environ.get("IFC_API_TOKEN", "")
ALLOWED_ORIGIN = os.environ.get("IFC_ALLOWED_ORIGIN", "").rstrip("/")
LEGACY_ENABLED = os.environ.get("IFC_ENABLE_LEGACY_API_TOKEN") == "true"


def connect_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, connect_timeout=10)


def authentication_service():
    try:
        secret = bytes.fromhex(os.environ.get("IFC_SESSION_SECRET_HEX", ""))
    except ValueError as exc:
        raise RuntimeError("Invalid session secret") from exc
    return AuthenticationService(DATABASE_URL, secret)


def initialize_database():
    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS measurements (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                payload JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


def validate_subcontractor(data):
    allowed = ("company_name", "contact_name", "contact_email")
    if any(key not in allowed for key in data):
        return None
    if not isinstance(data.get("company_name"), str):
        return None
    name = data["company_name"].strip()
    if not name or len(name) > 200:
        return None
    result = {"company_name": name}
    for key in ("contact_name", "contact_email"):
        value = data.get(key)
        if value is not None:
            if not isinstance(value, str) or len(value) > 254:
                return None
            value = value.strip() or None
        result[key] = value
    if result["contact_email"] and (
        "@" not in result["contact_email"]
        or any(ch.isspace() for ch in result["contact_email"])
    ):
        return None
    return result


class Handler(BaseHTTPRequestHandler):
    def cors_headers(self):
        if ALLOWED_ORIGIN and self.headers.get("Origin") == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Vary", "Origin")

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.cors_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def bearer(self):
        value = self.headers.get("Authorization", "")
        return value[7:] if value.startswith("Bearer ") and len(value) <= 4103 else ""

    def authorized(self):
        """Existing shared API key, explicitly disabled by default."""
        supplied = self.bearer()
        if (not LEGACY_ENABLED or len(API_TOKEN) < 32 or not supplied
                or not hmac.compare_digest(supplied, API_TOKEN)):
            self.send_json(401, {"status": "error", "message": "Unauthorized"})
            return False
        return True

    def authorize_user(self, permission=None):
        token = self.bearer()
        if not token:
            self.send_json(401, {"status": "error", "message": "Unauthorized"})
            return None
        try:
            service = authentication_service()
            user = service.authenticate(token)
            if user is None:
                self.send_json(401, {"status": "error", "message": "Unauthorized"})
                return None
            if permission and not service.has_permission(user["id"], permission):
                self.send_json(403, {"status": "error", "message": "Forbidden"})
                return None
            return user
        except (psycopg.Error, RuntimeError, ValueError):
            logging.exception("Authorization failed")
            self.send_json(503, {"status": "error", "message": "Authentication unavailable"})
            return None

    def authorize_project(self, project_id, permission):
        user = self.authorize_user()
        if user is None:
            return None
        try:
            if not authentication_service().can_access_project(
                user["id"], project_id, permission
            ):
                self.send_json(403, {"status": "error", "message": "Forbidden"})
                return None
            return user
        except (psycopg.Error, RuntimeError, ValueError):
            logging.exception("Project authorization failed")
            self.send_json(503, {"status": "error", "message": "Authentication unavailable"})
            return None

    def allow_subcontractors(self):
        token = self.bearer()
        if (LEGACY_ENABLED and len(API_TOKEN) >= 32 and token
                and hmac.compare_digest(token, API_TOKEN)):
            return True
        return self.authorize_user("subcontractors.manage") is not None

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def read_json_object(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                self.send_json(413, {"status": "error", "message": "Invalid request size"})
                return None
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(data, dict):
                self.send_json(400, {"status": "error", "message": "Expected JSON object"})
                return None
            return data
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {"status": "error", "message": "Invalid JSON"})
            return None

    def handle_user_login(self):
        data = self.read_json_object()
        if data is None:
            return
        if (set(data) != {"email", "password"}
                or not isinstance(data.get("email"), str)
                or not isinstance(data.get("password"), str)
                or len(data["email"]) > 254 or len(data["password"]) > 1024):
            return self.send_json(400, {"status": "error", "message": "Invalid request"})
        try:
            return self.send_json(
                200, authentication_service().login(data["email"], data["password"])
            )
        except AuthenticationError:
            return self.send_json(401, {"status": "error", "message": "Invalid credentials"})
        except (psycopg.Error, RuntimeError, ValueError):
            logging.exception("Login failed")
            return self.send_json(503, {"status": "error", "message": "Authentication unavailable"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/v1/auth/login":
            return self.handle_user_login()
        if path not in ("/api/v1/measurements", "/api/v1/subcontractors"):
            return self.send_json(404, {"error": "not_found"})
        # Measurements currently have no project owner: legacy staging only.
        if path == "/api/v1/measurements":
            if not self.authorized():
                return
        elif not self.allow_subcontractors():
            return
        data = self.read_json_object()
        if data is None:
            return
        if path == "/api/v1/subcontractors":
            clean = validate_subcontractor(data)
            if clean is None:
                return self.send_json(400, {
                    "status": "error", "message": "Invalid subcontractor data"
                })
            try:
                with connect_db() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO subcontractors
                                (company_name, contact_name, contact_email)
                            VALUES (%s, %s, %s)
                            RETURNING id, company_name, contact_name,
                                      contact_email, created_at
                        """, (clean["company_name"], clean["contact_name"], clean["contact_email"]))
                        row = cur.fetchone()
                return self.send_json(201, {"status": "created", "subcontractor": {
                    "id": row[0], "company_name": row[1],
                    "contact_name": row[2], "contact_email": row[3],
                    "created_at": row[4].isoformat()
                }})
            except psycopg.Error:
                logging.exception("Subcontractor insert failed")
                return self.send_json(503, {"status": "error", "message": "Database unavailable"})
        try:
            with connect_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO measurements (payload) VALUES (%s) RETURNING id, created_at",
                        (Jsonb(data),)
                    )
                    item_id, created_at = cur.fetchone()
            return self.send_json(200, {
                "status": "received", "message": "Aufmaßdaten erfolgreich empfangen",
                "id": item_id, "created_at": created_at.isoformat(), "data": data
            })
        except psycopg.Error:
            logging.exception("Measurement insert failed")
            return self.send_json(503, {"status": "error", "message": "Database unavailable"})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            return self.send_json(200, {
                "service": "ifc-digital-staging",
                "status": "ok", "environment": "staging"
            })
        if path == "/api/v1/auth/me":
            user = self.authorize_user()
            if user is not None:
                return self.send_json(200, {"status": "ok", "user": user})
            return
        if path == "/api/v1/test-project":
            if self.authorize_project("PRJ-0041", "projects.read") is None:
                return
            return self.send_json(200, {
                "project_id": "PRJ-0041", "window_id": "W-0037",
                "revision": 6, "test_data": True
            })
        if path not in ("/api/v1/subcontractors", "/api/v1/measurements"):
            return self.send_json(404, {"error": "not_found"})
        if path == "/api/v1/measurements":
            if not self.authorized():
                return
        elif not self.allow_subcontractors():
            return
        if path == "/api/v1/subcontractors":
            try:
                with connect_db() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT id, company_name, contact_name,
                                   contact_email, created_at
                            FROM subcontractors
                            ORDER BY id ASC LIMIT 1000
                        """)
                        rows = cur.fetchall()
                return self.send_json(200, {"status": "ok", "subcontractors": [
                    {"id": r[0], "company_name": r[1],
                     "contact_name": r[2], "contact_email": r[3],
                     "created_at": r[4].isoformat()} for r in rows
                ]})
            except psycopg.Error:
                logging.exception("Subcontractor read failed")
                return self.send_json(503, {"status": "error", "message": "Database unavailable"})
        try:
            with connect_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT payload FROM measurements ORDER BY id ASC LIMIT 1000")
                    rows = cur.fetchall()
            return self.send_json(200, {
                "status": "ok", "measurements": [r[0] for r in rows]
            })
        except psycopg.Error:
            logging.exception("Measurement read failed")
            return self.send_json(503, {"status": "error", "message": "Database unavailable"})


if __name__ == "__main__":
    if LEGACY_ENABLED and len(API_TOKEN) < 32:
        raise RuntimeError("IFC_API_TOKEN must contain at least 32 characters")
    authentication_service()
    initialize_database()
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
