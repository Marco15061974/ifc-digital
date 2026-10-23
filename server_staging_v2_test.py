"""IFC Digital staging HTTP integration tests (isolated mocks, no real DB)."""
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import urlencode

import server_staging_v2 as staging
from project_assignments import AssignmentError


class StagingHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), staging.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.user = {'id': 1}
        self.auth_patch = patch.object(staging.Handler, 'authorize_user', return_value=self.user)
        self.auth_patch.start()
        self.service_patch = patch.object(staging.server, 'authentication_service')
        self.service = self.service_patch.start()
        self.api_patch = patch.object(staging, 'ProjectAssignmentAPI')
        self.api = self.api_patch.start().return_value

    def tearDown(self):
        self.api_patch.stop()
        self.service_patch.stop()
        self.auth_patch.stop()

    def request(self, method, path, payload=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        body = json.dumps(payload) if payload is not None else None
        headers = {'Content-Type': 'application/json'} if body is not None else {}
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            conn.close()

    def test_assign_success(self):
        self.api.assign.return_value = {'status': 'assigned'}
        payload = {'user_id': 42, 'project_id': 'PRJ-001', 'role': 'viewer'}
        status, data = self.request('POST', staging.ASSIGNMENTS_PATH, payload)
        self.assertEqual(status, 201)
        self.assertEqual(data['status'], 'assigned')
        self.api.assign.assert_called_once_with(1, payload)

    def test_list_success(self):
        self.api.list_assignments.return_value = {'status': 'ok', 'assignments': [], 'count': 0}
        path = staging.ASSIGNMENTS_PATH + '?' + urlencode({'project_id': 'PRJ-001'})
        status, data = self.request('GET', path)
        self.assertEqual(status, 200)
        self.assertEqual(data['count'], 0)
        self.api.list_assignments.assert_called_once_with(1, 'PRJ-001')

    def test_revoke_success(self):
        self.api.revoke.return_value = {'status': 'revoked'}
        payload = {'user_id': 42, 'project_id': 'PRJ-001'}
        status, data = self.request('POST', staging.REVOKE_PATH, payload)
        self.assertEqual(status, 200)
        self.assertEqual(data['status'], 'revoked')
        self.api.revoke.assert_called_once_with(1, payload)

    def test_missing_project_id(self):
        status, data = self.request('GET', staging.ASSIGNMENTS_PATH)
        self.assertEqual(status, 400)
        self.api.list_assignments.assert_not_called()

    def test_duplicate_project_id(self):
        status, _ = self.request('GET', staging.ASSIGNMENTS_PATH + '?project_id=A&project_id=B')
        self.assertEqual(status, 400)
        self.api.list_assignments.assert_not_called()

    def test_unknown_query_field(self):
        status, _ = self.request('GET', staging.ASSIGNMENTS_PATH + '?project_id=A&admin=true')
        self.assertEqual(status, 400)
        self.api.list_assignments.assert_not_called()

    def test_assignment_validation_error(self):
        self.api.assign.side_effect = AssignmentError('Invalid assignment')
        status, data = self.request('POST', staging.ASSIGNMENTS_PATH, {'user_id': 42})
        self.assertEqual(status, 400)
        self.assertEqual(data['status'], 'error')

    def test_assignment_permission_denied(self):
        self.api.assign.side_effect = PermissionError('Denied')
        status, data = self.request('POST', staging.ASSIGNMENTS_PATH, {'user_id': 42, 'project_id': 'PRJ-001'})
        self.assertEqual(status, 403)
        self.assertEqual(data['message'], 'Forbidden')

    def test_list_permission_denied(self):
        self.api.list_assignments.side_effect = PermissionError('Denied')
        status, data = self.request('GET', staging.ASSIGNMENTS_PATH + '?project_id=PRJ-001')
        self.assertEqual(status, 403)
        self.assertEqual(data['message'], 'Forbidden')

    def test_revoke_permission_denied(self):
        self.api.revoke.side_effect = PermissionError('Denied')
        status, data = self.request('POST', staging.REVOKE_PATH, {'user_id': 42, 'project_id': 'PRJ-001'})
        self.assertEqual(status, 403)
        self.assertEqual(data['message'], 'Forbidden')

    def test_database_unavailable(self):
        self.api.list_assignments.side_effect = RuntimeError('Database unavailable')
        status, data = self.request('GET', staging.ASSIGNMENTS_PATH + '?project_id=PRJ-001')
        self.assertEqual(status, 503)
        self.assertEqual(data['message'], 'Service unavailable')

    def test_missing_session(self):
        # Use the real authorize_user implementation with no Authorization header.
        # It sends a 401 JSON response without contacting the database.
        self.auth_patch.stop()
        try:
            status, data = self.request('GET', staging.ASSIGNMENTS_PATH + '?project_id=PRJ-001')
        finally:
            self.auth_patch.start()
        self.assertEqual(status, 401)
        self.assertEqual(data['message'], 'Unauthorized')
        self.api.list_assignments.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
