"""IFC Digital staging server with project-assignment HTTP routes.

Not production ready. Reuses the existing server for all older routes.
"""

import logging
import os
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import psycopg

import server
from project_assignments import AssignmentError
from project_assignments_api import ProjectAssignmentAPI

ASSIGNMENTS_PATH = "/api/v1/project-assignments"
REVOKE_PATH = ASSIGNMENTS_PATH + "/revoke"


class Handler(server.Handler):
    """Add session-protected assignment routes without changing old routes."""

    def assignment_request(self, operation):
        # Only personal sessions are accepted; never use the legacy API key.
        user = self.authorize_user()
        if user is None:
            return

        if operation == "list":
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if set(params) != {"project_id"} or len(params["project_id"]) != 1:
                return self.send_json(400, {"status": "error", "message": "Invalid project_id"})
            project_id = params["project_id"][0]
            data = None
        else:
            data = self.read_json_object()
            if data is None:
                return

        try:
            api = ProjectAssignmentAPI(server.authentication_service())
            if operation == "assign":
                result = api.assign(user["id"], data)
                status = 201
            elif operation == "revoke":
                result = api.revoke(user["id"], data)
                status = 200
            else:
                result = api.list_assignments(user["id"], project_id)
                status = 200
            return self.send_json(status, result)
        except AssignmentError:
            return self.send_json(400, {"status": "error", "message": "Invalid assignment request"})
        except PermissionError:
            return self.send_json(403, {"status": "error", "message": "Forbidden"})
        except (psycopg.Error, RuntimeError, ValueError):
            logging.exception("Project assignment service unavailable")
            return self.send_json(503, {"status": "error", "message": "Service unavailable"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == ASSIGNMENTS_PATH:
            return self.assignment_request("assign")
        if path == REVOKE_PATH:
            return self.assignment_request("revoke")
        return super().do_POST()

    def do_GET(self):
        if urlsplit(self.path).path == ASSIGNMENTS_PATH:
            return self.assignment_request("list")
        return super().do_GET()


if __name__ == "__main__":
    if server.LEGACY_ENABLED and len(server.API_TOKEN) < 32:
        raise RuntimeError("IFC_API_TOKEN must contain at least 32 characters")
    server.authentication_service()
    server.initialize_database()
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
