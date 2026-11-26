"""IFC Digital - Staging V4 HTTP and security tests."""

import base64
import hashlib
import http.client
import threading
import unittest

from http.server import ThreadingHTTPServer
from unittest.mock import patch

import server_staging_v4 as v4
import server_staging_v3 as v3


class StagingV4Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            v4.Handler,
        )

        cls.port = cls.httpd.server_address[1]

        cls.thread = threading.Thread(
            target=cls.httpd.serve_forever,
            daemon=True,
        )

        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def request(self, method, path, headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.port,
            timeout=10,
        )

        try:
            connection.request(
                method,
                path,
                headers=headers or {},
            )

            response = connection.getresponse()

            return (
                response.status,
                dict(response.getheaders()),
                response.read(),
            )

        finally:
            connection.close()

    def test_01_premium_available(self):
        status, headers, body = self.request(
            "GET",
            "/premium",
        )

        self.assertEqual(status, 200)

        self.assertEqual(
            headers.get("Content-Type"),
            "text/html; charset=utf-8",
        )

        self.assertEqual(body, v4.load_ui())

        self.assertIn(b"IFC Digital", body)

        self.assertIn(
            b'id="loginForm"',
            body,
        )

    def test_02_security_headers(self):
        status, headers, body = self.request(
            "GET",
            "/premium",
        )

        self.assertEqual(status, 200)

        self.assertEqual(
            headers.get("Cache-Control"),
            "no-store",
        )

        self.assertEqual(
            headers.get("X-Content-Type-Options"),
            "nosniff",
        )

        self.assertEqual(
            headers.get("X-Frame-Options"),
            "DENY",
        )

        self.assertEqual(
            headers.get("Referrer-Policy"),
            "no-referrer",
        )

        self.assertEqual(
            int(headers["Content-Length"]),
            len(body),
        )

        self.assertIn(
            "camera=()",
            headers.get("Permissions-Policy", ""),
        )

    def test_03_content_security_policy(self):
        status, headers, body = self.request(
            "GET",
            "/premium",
        )

        self.assertEqual(status, 200)

        csp = headers.get(
            "Content-Security-Policy",
            "",
        )

        self.assertIn("default-src 'none'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("form-action 'none'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'none'", csp)

        self.assertNotIn("'unsafe-eval'", csp)

        self.assertEqual(
            body.count(b"<script>"),
            1,
        )

        self.assertEqual(
            body.count(b"</script>"),
            1,
        )

        script = body.split(
            b"<script>",
            1,
        )[1].split(
            b"</script>",
            1,
        )[0]

        digest = base64.b64encode(
            hashlib.sha256(script).digest()
        ).decode("ascii")

        self.assertIn(
            "script-src 'sha256-" + digest + "'",
            csp,
        )

    def test_04_head_request(self):
        status, headers, body = self.request(
            "HEAD",
            "/premium",
        )

        self.assertEqual(status, 200)
        self.assertEqual(body, b"")

        self.assertEqual(
            int(headers["Content-Length"]),
            len(v4.load_ui()),
        )

    def test_05_private_files_not_served(self):
        paths = [
            "/server.py",
            "/auth.py",
            "/.env",
            "/server_staging_v4.py",
            "/sprint342/server_staging_v4.py",
            "/sprint342/ifc_premium_v2_staging.html",
        ]

        for path in paths:
            with self.subTest(path=path):
                status, headers, body = self.request(
                    "GET",
                    path,
                )

                self.assertEqual(status, 404)

    def test_06_v3_api_inheritance(self):
        self.assertTrue(
            issubclass(
                v4.Handler,
                v3.Handler,
            )
        )

        self.assertIs(
            v4.Handler.do_POST,
            v3.Handler.do_POST,
        )

        self.assertIs(
            v4.Handler.do_OPTIONS,
            v3.Handler.do_OPTIONS,
        )

    def test_07_unauthorized_user(self):
        status, headers, body = self.request(
            "GET",
            "/api/v1/auth/me",
        )

        self.assertEqual(status, 401)

    def test_08_unauthorized_project_access(self):
        status, headers, body = self.request(
            "GET",
            "/api/v1/project-permissions/check"
            "?project_id=PRJ-DEMO-001"
            "&permission=projects.read",
        )

        self.assertEqual(status, 401)

    def test_09_missing_ui(self):
        with patch.object(
            v4,
            "load_ui",
            side_effect=OSError("Test"),
        ):
            status, headers, body = self.request(
                "GET",
                "/premium",
            )

        self.assertEqual(status, 503)

    def test_10_invalid_ui(self):
        with patch.object(
            v4,
            "load_ui",
            return_value=b"<html>Invalid UI</html>",
        ):
            status, headers, body = self.request(
                "GET",
                "/premium",
            )

        self.assertEqual(status, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
