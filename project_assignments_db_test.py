
"""IFC Digital - PostgreSQL Project Assignment Tests.

Integration tests using an isolated PostgreSQL database.
No production data must be used.
"""

import os
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parent
MIGRATIONS = ROOT / "database" / "migrations"

DATABASE_URL = os.environ.get(
    "IFC_TEST_DATABASE_URL", ""
)

EXPECTED_DB = "ifc_assignments_test"


class ProjectAssignmentsDatabaseTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not DATABASE_URL:
            raise RuntimeError(
                "IFC_TEST_DATABASE_URL is required"
            )

        cls.connection = psycopg.connect(DATABASE_URL)
        cls.connection.autocommit = True
        cls.schema = None

        database_name = cls.connection.execute(
            "SELECT current_database()"
        ).fetchone()[0]

        if database_name != EXPECTED_DB:
            cls.connection.close()
            raise RuntimeError(
                "Unsafe database name: "
                + database_name
            )

        cls.schema = "ifc_test_" + uuid.uuid4().hex[:16]

        try:
            cls.connection.execute(
                sql.SQL("CREATE SCHEMA {}").format(
                    sql.Identifier(cls.schema)
                )
            )

            cls.connection.execute(
                sql.SQL(
                    "SET search_path TO {}"
                ).format(sql.Identifier(cls.schema))
            )

            for filename in (
                "001_subcontractor_schema.sql",
                "002_users_roles_schema.sql",
                "003_project_assignments_schema.sql",
            ):
                migration = (
                    MIGRATIONS / filename
                ).read_text(encoding="utf-8")

                cls.connection.execute(migration)

        except Exception:
            cls.cleanup_database()
            raise

    @classmethod
    def cleanup_database(cls):
        connection = getattr(
            cls, "connection", None
        )
        if connection is None:
            return

        try:
            schema = getattr(cls, "schema", None)

            if schema:
                connection.rollback()
                connection.execute(
                    sql.SQL(
                        "DROP SCHEMA IF EXISTS {} CASCADE"
                    ).format(sql.Identifier(schema))
                )
        finally:
            connection.close()
            cls.connection = None

    @classmethod
    def tearDownClass(cls):
        cls.cleanup_database()

    def setUp(self):
        self.connection.execute("BEGIN")

        email = (
            "ifc-test-"
            + uuid.uuid4().hex
            + "@example.test"
        )

        self.user_id = self.connection.execute(
            """
            INSERT INTO ifc_users
                (email, display_name)
            VALUES (%s, %s)
            RETURNING id
            """,
            (email, "IFC Test Monteur")
        ).fetchone()[0]

        self.project_id = "PRJ-TEST-001"

    def tearDown(self):
        # Also resets a failed PostgreSQL transaction.
        self.connection.rollback()

    def assign(self, role="viewer"):
        return self.connection.execute(
            """
            INSERT INTO ifc_project_access
                (user_id, project_id, access_role)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (
                self.user_id,
                self.project_id,
                role
            )
        ).fetchone()[0]

    def test_assignment_is_stored(self):
        assignment_id = self.assign()

        row = self.connection.execute(
            """
            SELECT user_id, project_id, access_role
            FROM ifc_project_access
            WHERE id = %s
            """,
            (assignment_id,)
        ).fetchone()

        self.assertEqual(
            row,
            (
                self.user_id,
                self.project_id,
                "viewer"
            )
        )

    def test_duplicate_assignment_is_blocked(self):
        self.assign()

        with self.assertRaises(
            psycopg.errors.UniqueViolation
        ):
            self.assign()

    def test_revocation_is_stored(self):
        assignment_id = self.assign()

        self.connection.execute(
            """
            UPDATE ifc_project_access
            SET revoked_at = NOW()
            WHERE id = %s
            """,
            (assignment_id,)
        )

        row = self.connection.execute(
            """
            SELECT revoked_at
            FROM ifc_project_access
            WHERE id = %s
            """,
            (assignment_id,)
        ).fetchone()

        self.assertIsNotNone(row[0])

    def test_reassignment_after_revocation(self):
        first_id = self.assign()

        self.connection.execute(
            """
            UPDATE ifc_project_access
            SET revoked_at = NOW()
            WHERE id = %s
            """,
            (first_id,)
        )

        second_id = self.assign()

        self.assertNotEqual(
            first_id,
            second_id
        )

        count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM ifc_project_access
            WHERE user_id = %s
              AND project_id = %s
              AND revoked_at IS NULL
            """,
            (
                self.user_id,
                self.project_id
            )
        ).fetchone()[0]

        self.assertEqual(count, 1)

    def test_invalid_role_is_rejected(self):
        with self.assertRaises(
            psycopg.errors.CheckViolation
        ):
            self.assign("unknown-role")

    def test_revoked_history_is_preserved(self):
        first_id = self.assign()

        self.connection.execute(
            """
            UPDATE ifc_project_access
            SET revoked_at = NOW()
            WHERE id = %s
            """,
            (first_id,)
        )

        self.assign("editor")

        rows = self.connection.execute(
            """
            SELECT access_role, revoked_at
            FROM ifc_project_access
            WHERE user_id = %s
              AND project_id = %s
            ORDER BY id
            """,
            (
                self.user_id,
                self.project_id
            )
        ).fetchall()

        self.assertEqual(len(rows), 2)
        self.assertIsNotNone(rows[0][1])
        self.assertEqual(rows[1][0], "editor")
        self.assertIsNone(rows[1][1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
