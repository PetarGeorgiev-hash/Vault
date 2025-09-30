CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    pw_salt BYTEA NOT NULL,
    pw_params TEXT NOT NULL,
    pw_hash BYTEA NOT NULL,
    mk_salt BYTEA NOT NULL,
    mk_params TEXT NOT NULL,
    enc_root_key BYTEA NOT NULL,
    secret_key TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);