CREATE TABLE room_files (
    id UUID PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    encrypted_descriptor BYTEA,
    chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (chunk_count BETWEEN 0 AND 20000),
    encrypted_bytes BIGINT NOT NULL DEFAULT 0 CHECK (encrypted_bytes BETWEEN 0 AND 262148000),
    status VARCHAR(12) NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'complete')),
    manifest_sha256 CHAR(64),
    receipt JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK ((status = 'complete') = (completed_at IS NOT NULL)),
    CHECK ((status = 'complete') = (manifest_sha256 IS NOT NULL))
);

CREATE TABLE room_file_envelopes (
    file_id UUID NOT NULL REFERENCES room_files(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    enc BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    PRIMARY KEY (file_id, recipient_id),
    CHECK (octet_length(enc) = 65)
);

CREATE TABLE room_file_chunks (
    file_id UUID NOT NULL REFERENCES room_files(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index BETWEEN 0 AND 19999),
    ciphertext BYTEA NOT NULL,
    sha256 CHAR(64) NOT NULL,
    PRIMARY KEY (file_id, chunk_index),
    CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592)
);

CREATE INDEX room_files_room_idx ON room_files(room_id, created_at DESC) WHERE status = 'complete';
CREATE INDEX room_files_stale_idx ON room_files(created_at, room_id, id) WHERE status = 'uploading';

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
    'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
    'join_requested', 'member_approved', 'member_denied', 'member_revoked',
    'submission_cleanup_enabled', 'submissions_purged', 'file_published'
));
