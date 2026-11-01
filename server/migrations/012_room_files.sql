CREATE TABLE room_file_keys (
  room_id UUID PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
  fingerprint CHAR(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE room_files (
  id UUID PRIMARY KEY,
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  uploader_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  descriptor BYTEA NOT NULL CHECK (octet_length(descriptor) BETWEEN 1 AND 8192),
  chunk_count INTEGER NOT NULL CHECK (chunk_count BETWEEN 1 AND 250),
  encrypted_bytes BIGINT NOT NULL CHECK (encrypted_bytes BETWEEN 16 AND 262148000),
  manifest_sha256 CHAR(64) CHECK (manifest_sha256 IS NULL OR manifest_sha256 ~ '^[0-9a-f]{64}$'),
  status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading','complete')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  completed_at TIMESTAMPTZ,
  CHECK ((status = 'uploading' AND completed_at IS NULL AND manifest_sha256 IS NULL) OR
         (status = 'complete' AND completed_at IS NOT NULL AND manifest_sha256 IS NOT NULL))
);
CREATE INDEX room_files_room_page ON room_files(room_id, created_at DESC, id DESC) WHERE status = 'complete';
CREATE INDEX room_files_upload_age ON room_files(created_at, id) WHERE status = 'uploading';

CREATE TABLE room_file_chunks (
  file_id UUID NOT NULL REFERENCES room_files(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL CHECK (chunk_index BETWEEN 0 AND 249),
  ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048592),
  sha256 CHAR(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (file_id, chunk_index)
);
