
-- IFC Digital
-- Migration 003: Project Assignments
-- PostgreSQL development environment
-- Requires migration 002
-- Test in an isolated database first.

BEGIN;

-- Remove old uniqueness constraint.
ALTER TABLE ifc_project_access
DROP CONSTRAINT IF EXISTS
    ifc_project_access_user_id_project_id_key;

-- Prevent duplicate non-revoked assignments.
CREATE UNIQUE INDEX IF NOT EXISTS
    idx_ifc_project_access_current
ON ifc_project_access (
    user_id,
    project_id
)
WHERE revoked_at IS NULL;

-- Improve project assignment lookups.
CREATE INDEX IF NOT EXISTS
    idx_ifc_project_access_active
ON ifc_project_access (
    project_id,
    user_id
)
WHERE revoked_at IS NULL;

-- Improve user assignment lookups.
CREATE INDEX IF NOT EXISTS
    idx_ifc_project_access_user
ON ifc_project_access (
    user_id,
    project_id
);

COMMIT;
