-- Public room receiving key only. Its private half travels in the trusted
-- invitation fragment and stays in browsers; it is never persisted by the API.
CREATE TABLE room_access_keys (
 room_id UUID PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
 public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 65 AND get_byte(public_key, 0) = 4),
 fingerprint CHAR(64) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE room_file_shared_envelopes (
 file_id UUID PRIMARY KEY REFERENCES room_files(id) ON DELETE CASCADE,
 fingerprint CHAR(64) NOT NULL,
 enc BYTEA NOT NULL CHECK (octet_length(enc) = 65),
 ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) = 48)
);
