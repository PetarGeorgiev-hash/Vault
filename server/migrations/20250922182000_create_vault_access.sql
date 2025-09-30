CREATE TABLE IF NOT EXISTS vault_access (
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX IF NOT EXISTS vault_access_user_idx ON vault_access(user_id);
CREATE INDEX IF NOT EXISTS vault_access_vault_idx ON vault_access(vault_id);