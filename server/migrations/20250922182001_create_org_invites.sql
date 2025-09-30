CREATE TABLE IF NOT EXISTS org_invites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    token_hash BYTEA NOT NULL,
    invited_by UUID REFERENCES users(id) ON DELETE
    SET NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        accepted_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Fast lookup by token
CREATE INDEX IF NOT EXISTS org_invites_token_idx ON org_invites(token_hash);
-- Prevent multiple *pending* invites to same email in same org
CREATE UNIQUE INDEX IF NOT EXISTS org_invites_unique_pending ON org_invites(org_id, email)
WHERE accepted_at IS NULL;