import os
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    
    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
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
        if self.path == "/api/v1/measurements":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(content_length)
                data = json.loads(body.decode("utf-8"))

                return self.send_json(200, {
                    "status": "received",
                    "message": "Aufmaßdaten erfolgreich empfangen",
                    "data": data
                })
            except Exception as error:
                return self.send_json(400, {
                    "status": "error",
                    "message": str(error)
                })

        return self.send_json(404, {"error": "not_found"})
    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {
                "service": "ifc-digital-staging",
                "status": "ok",
                "environment": "staging"
            })

        if self.path == "/api/v1/test-project":
            return self.send_json(200, {
                "project_id": "PRJ-0041",
                "window_id": "W-0037",
                "revision": 6,
                "test_data": True
            })

        return self.send_json(404, {"error": "not_found"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
