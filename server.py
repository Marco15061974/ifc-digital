
import json
import hmac
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import psycopg
from psycopg.types.json import Jsonb

logging.basicConfig(level=logging.INFO)
DATABASE_URL = os.environ.get('DATABASE_URL')
MAX_BODY_BYTES = 1024 * 1024
API_TOKEN = os.environ.get('IFC_API_TOKEN', '')
ALLOWED_ORIGIN = os.environ.get('IFC_ALLOWED_ORIGIN', '').rstrip('/')


def connect_db():
    if not DATABASE_URL:
        raise RuntimeError('DATABASE_URL is not configured')
    return psycopg.connect(DATABASE_URL, connect_timeout=10)


def initialize_database():
    with connect_db() as connection:
        with connection.cursor() as cursor:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS measurements (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            ''')


def validate_subcontractor(data):
    allowed = ('company_name', 'contact_name', 'contact_email')
    if any(key not in allowed for key in data):
        return None
    if not isinstance(data.get('company_name'), str):
        return None
    name = data['company_name'].strip()
    if not name or len(name) > 200:
        return None
    result = {'company_name': name}
    for key in ('contact_name', 'contact_email'):
        value = data.get(key)
        if value is not None:
            if not isinstance(value, str) or len(value) > 254:
                return None
            value = value.strip() or None
        result[key] = value
    if result['contact_email'] and (
        '@' not in result['contact_email'] or
        any(ch.isspace() for ch in result['contact_email'])
    ):
        return None
    return result


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.cors_headers()
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def cors_headers(self):
        origin = self.headers.get('Origin', '')
        if ALLOWED_ORIGIN and origin == ALLOWED_ORIGIN:
            self.send_header('Access-Control-Allow-Origin', ALLOWED_ORIGIN)
            self.send_header('Vary', 'Origin')

    def authorized(self):
        supplied = self.headers.get('Authorization', '')
        if not API_TOKEN or not supplied.startswith('Bearer '):
            self.send_json(401, {'status': 'error', 'message': 'Unauthorized'})
            return False
        if not hmac.compare_digest(supplied[7:], API_TOKEN):
            self.send_json(401, {'status': 'error', 'message': 'Unauthorized'})
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors_headers()
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def read_json_object(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > MAX_BODY_BYTES:
                self.send_json(413, {'status': 'error', 'message': 'Invalid request size'})
                return None
            data = json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(data, dict):
                self.send_json(400, {'status': 'error', 'message': 'Expected a JSON object'})
                return None
            return data
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {'status': 'error', 'message': 'Invalid JSON request'})
            return None

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ('/api/v1/measurements', '/api/v1/subcontractors'):
            return self.send_json(404, {'error': 'not_found'})
        if not self.authorized():
            return
        data = self.read_json_object()
        if data is None:
            return
        if path == '/api/v1/subcontractors':
            clean = validate_subcontractor(data)
            if clean is None:
                return self.send_json(400, {
                    'status': 'error', 'message': 'Invalid subcontractor data'
                })
            try:
                with connect_db() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute('''
                            INSERT INTO subcontractors
                                (company_name, contact_name, contact_email)
                            VALUES (%s, %s, %s)
                            RETURNING id, company_name, contact_name,
                                      contact_email, created_at
                        ''', (clean['company_name'], clean['contact_name'], clean['contact_email']))
                        row = cursor.fetchone()
                return self.send_json(201, {'status': 'created', 'subcontractor': {
                    'id': row[0], 'company_name': row[1],
                    'contact_name': row[2], 'contact_email': row[3],
                    'created_at': row[4].isoformat()
                }})
            except psycopg.Error:
                logging.exception('Subcontractor insert failed')
                return self.send_json(503, {'status': 'error', 'message': 'Database unavailable'})
        try:
            with connect_db() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        'INSERT INTO measurements (payload) VALUES (%s) RETURNING id, created_at',
                        (Jsonb(data),),
                    )
                    measurement_id, created_at = cursor.fetchone()
            return self.send_json(200, {
                'status': 'received',
                'message': 'Aufmaßdaten erfolgreich empfangen',
                'id': measurement_id,
                'created_at': created_at.isoformat(),
                'data': data,
            })
        except psycopg.Error:
            logging.exception('Database insert failed')
            return self.send_json(503, {'status': 'error', 'message': 'Database unavailable'})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/health':
            return self.send_json(200, {
                'service': 'ifc-digital-staging',
                'status': 'ok',
                'environment': 'staging',
            })
        if path == '/api/v1/test-project':
            if not self.authorized():
                return
            return self.send_json(200, {
                'project_id': 'PRJ-0041',
                'window_id': 'W-0037',
                'revision': 6,
                'test_data': True,
            })
        if path == '/api/v1/subcontractors':
            if not self.authorized():
                return
            try:
                with connect_db() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute('''
                            SELECT id, company_name, contact_name,
                                   contact_email, created_at
                            FROM subcontractors
                            ORDER BY id ASC LIMIT 1000
                        ''')
                        rows = cursor.fetchall()
                return self.send_json(200, {'status': 'ok', 'subcontractors': [
                    {'id': r[0], 'company_name': r[1], 'contact_name': r[2],
                     'contact_email': r[3], 'created_at': r[4].isoformat()}
                    for r in rows
                ]})
            except psycopg.Error:
                logging.exception('Subcontractor read failed')
                return self.send_json(503, {'status': 'error', 'message': 'Database unavailable'})
        if path == '/api/v1/measurements':
            if not self.authorized():
                return
            try:
                with connect_db() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT payload FROM measurements ORDER BY id ASC LIMIT 1000')
                        rows = cursor.fetchall()
                return self.send_json(200, {
                    'status': 'ok',
                    'measurements': [row[0] for row in rows],
                })
            except psycopg.Error:
                logging.exception('Database read failed')
                return self.send_json(503, {'status': 'error', 'message': 'Database unavailable'})
        return self.send_json(404, {'error': 'not_found'})


if __name__ == '__main__':
    if len(API_TOKEN) < 32:
        raise RuntimeError('IFC_API_TOKEN must contain at least 32 characters')
    initialize_database()
    port = int(os.environ.get('PORT', '8080'))
    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()
