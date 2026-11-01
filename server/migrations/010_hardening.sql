CREATE TABLE credential_challenges (
 room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
 session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 challenge TEXT NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(room_id, session_id)
);
ALTER TABLE memberships ADD COLUMN credential_expires_at TIMESTAMPTZ;
CREATE TABLE credential_revocations (
 room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
 nullifier TEXT NOT NULL,
 revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(room_id, nullifier)
);
CREATE TABLE owner_recovery (
 room_id UUID PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
 token_hash CHAR(64) NOT NULL UNIQUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE request_budgets (
 key TEXT PRIMARY KEY, hits INTEGER NOT NULL, reset_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
 'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
 'join_requested', 'member_approved', 'member_denied', 'member_revoked',
 'key_registered', 'file_published', 'files_purged', 'credential_proved',
 'key_rotated', 'file_access_granted', 'ownership_recovered', 'file_deleted'
));
-- Existing v1 admissions cannot satisfy the new expiry/challenge policy.
UPDATE memberships SET status = 'pending', decided_at = NULL,
 credential_verified_at = NULL, credential_nullifier = NULL
 WHERE credential_verified_at IS NOT NULL AND status = 'approved';
CREATE INDEX credential_challenges_expiry_idx ON credential_challenges(expires_at);
CREATE INDEX request_budgets_expiry_idx ON request_budgets(reset_at);
