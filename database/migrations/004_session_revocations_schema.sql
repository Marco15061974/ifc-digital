-- IFC Digital - Migration 004
-- Persistent session revocations
-- Sprint 342 - Staging V5

BEGIN;

CREATE TABLE IF NOT EXISTS public.ifc_session_revocations (
    nonce TEXT PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES public.ifc_users(id)
        ON DELETE CASCADE,

    revoked_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT ifc_session_nonce_check
        CHECK (nonce ~ '^[0-9a-f]{32}$'),

    CONSTRAINT ifc_session_expiry_check
        CHECK (expires_at > revoked_at)
);

CREATE INDEX IF NOT EXISTS
    idx_ifc_session_revocations_expires
ON public.ifc_session_revocations (
    expires_at
);

CREATE INDEX IF NOT EXISTS
    idx_ifc_session_revocations_user
ON public.ifc_session_revocations (
    user_id
);

COMMIT;
