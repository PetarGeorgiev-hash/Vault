-- +goose Up
-- +goose StatementBegin
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('personal', 'business')),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE TABLE org_memberships (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX org_kind_idx ON organizations(kind);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS org_memberships;
DROP TABLE IF EXISTS organizations;
-- +goose StatementEnd