import json
import logging
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import psycopg
from psycopg.types.json import Jsonb

logging.basicConfig(level=logging.INFO)
DATABASE_URL = os.environ.get("DATABASE_URL")
MAX_BODY_BYTES = 1024 * 1024


def connect_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, connect_timeout=10)


def initialize_database():
    with connect_db() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS measurements (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        if urlsplit(self.path).path != "/api/v1/measurements":
            return self.send_json(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                return self.send_json(413, {"status": "error", "message": "Invalid request size"})
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(data, dict):
                return self.send_json(400, {"status": "error", "message": "Expected a JSON object"})
        except (ValueError, UnicodeDecodeError):
            return self.send_json(400, {"status": "error", "message": "Invalid JSON request"})
        try:
            with connect_db() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO measurements (payload) VALUES (%s) RETURNING id, created_at",
                        (Jsonb(data),),
                    )
                    measurement_id, created_at = cursor.fetchone()
            return self.send_json(200, {
                "status": "received",
                "message": "Aufmaßdaten erfolgreich empfangen",
                "id": measurement_id,
                "created_at": created_at.isoformat(),
                "data": data,
            })
        except psycopg.Error:
            logging.exception("Database insert failed")
            return self.send_json(503, {"status": "error", "message": "Database unavailable"})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            return self.send_json(200, {
                "service": "ifc-digital-staging",
                "status": "ok",
                "environment": "staging",
            })
        if path == "/api/v1/test-project":
            return self.send_json(200, {
                "project_id": "PRJ-0041",
                "window_id": "W-0037",
                "revision": 6,
                "test_data": True,
            })
        if path == "/api/v1/measurements":
            try:
                with connect_db() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT payload FROM measurements ORDER BY id ASC LIMIT 1000")
                        rows = cursor.fetchall()
                return self.send_json(200, {
                    "status": "ok",
                    "measurements": [row[0] for row in rows],
                })
            except psycopg.Error:
                logging.exception("Database read failed")
                return self.send_json(503, {"status": "error", "message": "Database unavailable"})
        return self.send_json(404, {"error": "not_found"})


if __name__ == "__main__":
    initialize_database()
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
