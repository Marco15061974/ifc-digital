
-- IFC Digital P1.2.4-A: Nachunternehmer-Nachweismanagement
-- PostgreSQL 18; migration for isolated development/test database
BEGIN;

CREATE TABLE IF NOT EXISTS subcontractors (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 company_name TEXT NOT NULL,
 contact_name TEXT,
 contact_email TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS document_types (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 code TEXT NOT NULL UNIQUE,
 label TEXT NOT NULL,
 requires_expiry BOOLEAN NOT NULL DEFAULT FALSE,
 active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS subcontractor_documents (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 subcontractor_id BIGINT NOT NULL REFERENCES subcontractors(id),
 document_type_id BIGINT NOT NULL REFERENCES document_types(id),
 version INTEGER NOT NULL CHECK(version > 0),
 storage_key TEXT NOT NULL UNIQUE,
 original_filename TEXT NOT NULL,
 content_type TEXT NOT NULL,
 sha256 CHAR(64) NOT NULL,
 issued_at DATE,
 expires_at DATE,
 status TEXT NOT NULL DEFAULT 'pending'
  CHECK(status IN ('pending','approved','rejected','superseded')),
 uploaded_by_user_id BIGINT,
 uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(subcontractor_id,document_type_id,version),
 CHECK(expires_at IS NULL OR issued_at IS NULL OR expires_at >= issued_at)
);

CREATE TABLE IF NOT EXISTS subcontractor_project_assignments (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 subcontractor_id BIGINT NOT NULL REFERENCES subcontractors(id),
 project_id TEXT NOT NULL,
 assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(subcontractor_id,project_id)
);

CREATE TABLE IF NOT EXISTS project_document_requirements (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 project_id TEXT NOT NULL,
 document_type_id BIGINT NOT NULL REFERENCES document_types(id),
 required BOOLEAN NOT NULL DEFAULT TRUE,
 UNIQUE(project_id,document_type_id)
);

CREATE TABLE IF NOT EXISTS document_reviews (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 document_id BIGINT NOT NULL REFERENCES subcontractor_documents(id),
 project_id TEXT,
 decision TEXT NOT NULL
  CHECK(decision IN ('approved','rejected','needs_information')),
 reviewer_user_id BIGINT NOT NULL,
 reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_subcontractor_documents_lookup
 ON subcontractor_documents(subcontractor_id,document_type_id,expires_at);

CREATE INDEX IF NOT EXISTS idx_project_assignments_project
 ON subcontractor_project_assignments(project_id);

CREATE INDEX IF NOT EXISTS idx_document_reviews_document
 ON document_reviews(document_id,reviewed_at DESC);

COMMIT;
