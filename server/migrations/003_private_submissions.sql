CREATE TABLE room_recipient_keys (
  room_id UUID PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK (octet_length(public_key) = 65 AND get_byte(public_key, 0) = 4)
);

CREATE TABLE session_recipient_keys (
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (room_id, session_id),
  CHECK (octet_length(public_key) = 65 AND get_byte(public_key, 0) = 4)
);

CREATE TABLE private_submissions (
  id UUID PRIMARY KEY,
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  submitter_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  encrypted_descriptor BYTEA,
  chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (chunk_count BETWEEN 0 AND 20000),
  encrypted_bytes BIGINT NOT NULL DEFAULT 0 CHECK (encrypted_bytes BETWEEN 0 AND 262144000),
  status VARCHAR(12) NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'complete')),
  manifest_sha256 CHAR(64),
  receipt JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at TIMESTAMPTZ,
  CHECK ((status = 'complete') = (completed_at IS NOT NULL)),
  CHECK ((status = 'complete') = (manifest_sha256 IS NOT NULL))
);

CREATE TABLE submission_envelopes (
  submission_id UUID NOT NULL REFERENCES private_submissions(id) ON DELETE CASCADE,
  recipient_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  enc BYTEA NOT NULL,
  ciphertext BYTEA NOT NULL,
  PRIMARY KEY (submission_id, recipient_id),
  CHECK (octet_length(enc) = 65)
);

CREATE TABLE submission_chunks (
  submission_id UUID NOT NULL REFERENCES private_submissions(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL CHECK (chunk_index BETWEEN 0 AND 19999),
  ciphertext BYTEA NOT NULL,
  sha256 CHAR(64) NOT NULL,
  PRIMARY KEY (submission_id, chunk_index),
  CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592)
);

CREATE INDEX private_submissions_room_idx ON private_submissions(room_id, created_at DESC) WHERE status = 'complete';
CREATE INDEX private_submissions_submitter_idx ON private_submissions(submitter_id, created_at DESC) WHERE status = 'complete';
