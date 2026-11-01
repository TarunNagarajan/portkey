ALTER TABLE room_file_keys
  ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1 CHECK (epoch BETWEEN 1 AND 32),
  ADD COLUMN history_envelope TEXT;

ALTER TABLE room_files
  ADD COLUMN key_fingerprint CHAR(64);

UPDATE room_files f
SET key_fingerprint = k.fingerprint
FROM room_file_keys k
WHERE f.room_id = k.room_id;

ALTER TABLE room_files
  ALTER COLUMN key_fingerprint SET NOT NULL,
  ADD CONSTRAINT room_files_key_fingerprint_format
    CHECK (key_fingerprint ~ '^[0-9a-f]{64}$');
