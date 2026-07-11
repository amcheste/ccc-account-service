CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id           uuid PRIMARY KEY,
    username     citext NOT NULL UNIQUE,
    display_name text NOT NULL,
    email        text,
    role         text NOT NULL CHECK (role IN ('admin', 'member')),
    status       text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    user_id       uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    kind          text NOT NULL DEFAULT 'password',
    password_hash text NOT NULL,
    must_change   boolean NOT NULL DEFAULT false,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL UNIQUE,
    device_name text,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    replaced_by uuid REFERENCES refresh_tokens (id)
);

CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
