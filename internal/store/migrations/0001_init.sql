-- meta holds the master key check: a constant sealed under the master key, so a wrong key fails
-- at start instead of at the first credential.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

-- key_hash is SHA-256 of the user's ghgw key; keys are looked up by its first 8 bytes.
CREATE TABLE users (
    name     TEXT PRIMARY KEY,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    key_hash BLOB NOT NULL UNIQUE CHECK (length(key_hash) = 32)
) STRICT;
CREATE INDEX users_key_selector ON users (substr(key_hash, 1, 8));

CREATE TABLE groups (
    name TEXT PRIMARY KEY
) STRICT;

CREATE TABLE group_members (
    group_name TEXT NOT NULL REFERENCES groups (name) ON DELETE CASCADE,
    user_name  TEXT NOT NULL REFERENCES users (name) ON DELETE CASCADE,
    PRIMARY KEY (group_name, user_name)
) STRICT;
CREATE INDEX group_members_user ON group_members (user_name);

-- AUTOINCREMENT: grant IDs are cited in decisions and audit records, so they are never reused.
-- repos and push are JSON arrays of patterns; api is '' for no REST operation.
CREATE TABLE grants (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name  TEXT REFERENCES users (name) ON DELETE CASCADE,
    group_name TEXT REFERENCES groups (name) ON DELETE CASCADE,
    repos      TEXT NOT NULL,
    access     TEXT NOT NULL,
    push       TEXT NOT NULL,
    api        TEXT NOT NULL,
    CHECK ((user_name IS NULL) <> (group_name IS NULL))
) STRICT;
CREATE INDEX grants_user ON grants (user_name);
CREATE INDEX grants_group ON grants (group_name);

-- credential is the owner's token sealed with AES-256-GCM under the master key: a 12-byte random
-- nonce, the ciphertext and the tag, with the lowercased owner as additional data. Times are Unix
-- seconds; expires_at is NULL when GitHub reported no expiry.
CREATE TABLE owners (
    name       TEXT PRIMARY KEY COLLATE NOCASE,
    credential BLOB NOT NULL,
    expires_at INTEGER,
    updated_at INTEGER NOT NULL
) STRICT;

-- token_hash is SHA-256 of the admin token; tokens are looked up by its first 8 bytes.
CREATE TABLE admin_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX admin_tokens_selector ON admin_tokens (substr(token_hash, 1, 8));
