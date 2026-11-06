"""IFC Digital - Sprint 342 - Staging Server V3.

Development only. Not production ready.
Reuses the existing V2 server and adds a protected
project permission check endpoint.

No changes to the existing server or Render deployment.
"""

import logging
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import server_staging_v2
from project_permissions import (
    PROJECT_PERMISSIONS,
    ProjectPermissionService,
)

CHECK_PATH = "/api/v1/project-permissions/check"


class Handler(server_staging_v2.Handler):
    """V2 routes plus a session-protected permission check."""

    def do_GET(self):
        parsed = urlsplit(self.path)

        if parsed.path != CHECK_PATH:
            return super().do_GET()

        # Only a validated personal session can be used.
        user = self.authorize_user()
        if user is None:
            return

        params = parse_qs(parsed.query, keep_blank_values=True)

        if (
            set(params) != {"project_id", "permission"}
            or len(params["project_id"]) != 1
            or len(params["permission"]) != 1
        ):
            return self.send_json(
                400,
                {"status": "error", "message": "Invalid parameters"},
            )

        project_id = params["project_id"][0]
        permission = params["permission"][0]

        if (
            not project_id
            or len(project_id) > 128
            or permission not in PROJECT_PERMISSIONS
        ):
            return self.send_json(
                400,
                {"status": "error", "message": "Invalid parameters"},
            )

        try:
            service = ProjectPermissionService(
                server_staging_v2.server.authentication_service()
            )
            result = service.check(
                user["id"], project_id, permission
            )
        except Exception:
            logging.exception("Project permission check failed")
            return self.send_json(
                503,
                {"status": "error", "message": "Service unavailable"},
            )

        if not result.allowed:
            return self.send_json(
                403,
                {"status": "error", "message": "Forbidden"},
            )

        return self.send_json(
            200,
            {
                "status": "ok",
                "allowed": True,
                "project_id": project_id,
                "permission": permission,
            },
        )


if __name__ == "__main__":
    import os
    from http.server import ThreadingHTTPServer

    server = server_staging_v2.server

    if server.LEGACY_ENABLED:
        raise RuntimeError(
            "Legacy API token must be disabled for V3"
        )

    server.authentication_service()
    server.initialize_database()

    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(
        ("0.0.0.0", port), Handler
    ).serve_forever()
