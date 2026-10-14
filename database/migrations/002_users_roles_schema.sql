
-- IFC Digital P1.2.4-B.3
-- Benutzer, Rollen und projektbezogene Berechtigungen
-- PostgreSQL 18 / Entwicklungsumgebung
-- Voraussetzung: 001_subcontractor_schema.sql

BEGIN;

-- Benutzerkonten
CREATE TABLE IF NOT EXISTS ifc_users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    account_type TEXT NOT NULL DEFAULT 'internal'
        CHECK (account_type IN ('internal', 'external')),
    subcontractor_id BIGINT REFERENCES subcontractors(id),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (length(trim(email)) > 3),
    CHECK (length(trim(display_name)) > 0),
    CHECK (
        account_type = 'external'
        OR subcontractor_id IS NULL
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ifc_users_email
    ON ifc_users (lower(email));

-- Benutzerrollen
CREATE TABLE IF NOT EXISTS ifc_roles (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Einzelne Berechtigungen
CREATE TABLE IF NOT EXISTS ifc_permissions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

-- Berechtigungen je Rolle
CREATE TABLE IF NOT EXISTS ifc_role_permissions (
    role_id BIGINT NOT NULL REFERENCES ifc_roles(id)
        ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES ifc_permissions(id)
        ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Rollen je Benutzer
CREATE TABLE IF NOT EXISTS ifc_user_roles (
    user_id BIGINT NOT NULL REFERENCES ifc_users(id)
        ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES ifc_roles(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Individuelle Berechtigungsausnahmen
CREATE TABLE IF NOT EXISTS ifc_user_permissions (
    user_id BIGINT NOT NULL REFERENCES ifc_users(id)
        ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES ifc_permissions(id),
    allowed BOOLEAN NOT NULL,
    PRIMARY KEY (user_id, permission_id)
);

-- Projektbezogene Benutzerfreigaben
CREATE TABLE IF NOT EXISTS ifc_project_access (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES ifc_users(id)
        ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    access_role TEXT NOT NULL
        CHECK (access_role IN (
            'manager',
            'editor',
            'viewer',
            'approver'
        )),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, project_id),
    CHECK (
        expires_at IS NULL
        OR expires_at > granted_at
    )
);

-- Nachvollziehbarkeit von Berechtigungsänderungen
CREATE TABLE IF NOT EXISTS ifc_access_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id BIGINT REFERENCES ifc_users(id),
    target_user_id BIGINT REFERENCES ifc_users(id),
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Standardrollen
INSERT INTO ifc_roles (code, label)
VALUES
    ('admin', 'Geschäftsführer / Admin'),
    ('office', 'Büro / Verwaltung'),
    ('surveyor', 'Aufmaßtechniker'),
    ('installer', 'Monteur'),
    ('subcontractor', 'Nachunternehmer'),
    ('client_manager', 'Externer Bauleiter')
ON CONFLICT (code) DO NOTHING;

-- Berechtigungskatalog
INSERT INTO ifc_permissions (code, description)
VALUES
    ('users.manage', 'Benutzer verwalten'),
    ('roles.manage', 'Rollen und Rechte verwalten'),
    ('projects.read', 'Projekte ansehen'),
    ('projects.manage', 'Projekte verwalten'),
    ('measurements.read', 'Aufmaße ansehen'),
    ('measurements.write', 'Aufmaße bearbeiten'),
    ('reports.read', 'Tagesrapporte ansehen'),
    ('reports.write', 'Tagesrapporte erstellen'),
    ('reports.approve', 'Tagesrapporte abnehmen'),
    ('photos.read', 'Projektfotos ansehen'),
    ('documents.read', 'Dokumente ansehen'),
    ('documents.upload', 'Dokumente hochladen'),
    ('documents.review', 'Nachweise prüfen'),
    ('subcontractors.manage', 'Nachunternehmer verwalten'),
    ('assignments.manage', 'Projektzuordnungen verwalten'),
    ('finance.read', 'Kalkulationen und Preise ansehen')
ON CONFLICT (code) DO NOTHING;

-- Nur administrative Grundrechte automatisch zuordnen
INSERT INTO ifc_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM ifc_roles r
CROSS JOIN ifc_permissions p
WHERE r.code = 'admin'
ON CONFLICT DO NOTHING;

-- Weitere Rollen erhalten ihre Rechte erst
-- nach bestätigter Berechtigungsmatrix.

CREATE INDEX IF NOT EXISTS idx_ifc_project_access_project
    ON ifc_project_access(project_id);

CREATE INDEX IF NOT EXISTS idx_ifc_access_audit_target
    ON ifc_access_audit(target_user_id, created_at DESC);

COMMIT;
