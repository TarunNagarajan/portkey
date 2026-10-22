ALTER TABLE rooms DROP CONSTRAINT rooms_admission_policy_check;
ALTER TABLE rooms ADD CONSTRAINT rooms_admission_policy_check
  CHECK (admission_policy IN ('approval', 'pass', 'proof'));

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
  'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
  'join_requested', 'member_approved', 'member_denied', 'member_revoked',
  'submission_cleanup_enabled', 'submissions_purged', 'admission_passes_issued', 'pass_revoked', 'pass_redeemed',
  'proof_enrollments_issued', 'proof_enrollment_revoked', 'proof_admitted'
));
ALTER TABLE room_activity DROP CONSTRAINT room_activity_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_check CHECK (
  (kind IN ('join_requested', 'member_approved', 'member_denied', 'member_revoked', 'pass_redeemed', 'proof_admitted'))
    = (member_label IS NOT NULL)
);

CREATE TABLE room_proof_invites (
  id UUID PRIMARY KEY,
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  invite_number INTEGER NOT NULL CHECK (invite_number > 0),
  token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  enrolled_commitment TEXT,
  UNIQUE (room_id, invite_number),
  CHECK (enrolled_commitment IS NULL OR enrolled_commitment ~ '^(0|[1-9][0-9]{0,76})$'),
  CHECK (revoked_at IS NULL OR enrolled_commitment IS NULL)
);

CREATE TABLE room_proof_commitments (
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  commitment TEXT NOT NULL CHECK (commitment ~ '^(0|[1-9][0-9]{0,76})$'),
  invite_id UUID NOT NULL UNIQUE REFERENCES room_proof_invites(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (room_id, commitment)
);

CREATE INDEX room_proof_invites_room_idx ON room_proof_invites(room_id, invite_number);
CREATE INDEX room_proof_commitments_room_idx ON room_proof_commitments(room_id, created_at, commitment);

CREATE TABLE room_proof_challenges (
  id UUID PRIMARY KEY,
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  accepted_root TEXT NOT NULL CHECK (accepted_root ~ '^(0|[1-9][0-9]{0,76})$'),
  scope TEXT NOT NULL CHECK (scope ~ '^(0|[1-9][0-9]{0,76})$'),
  message TEXT NOT NULL CHECK (message ~ '^(0|[1-9][0-9]{0,76})$'),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  UNIQUE (room_id, session_id)
);

CREATE TABLE room_proof_nullifiers (
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  nullifier TEXT NOT NULL CHECK (nullifier ~ '^(0|[1-9][0-9]{0,76})$'),
  session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
  challenge_id UUID REFERENCES room_proof_challenges(id) ON DELETE SET NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (room_id, nullifier)
);

CREATE INDEX room_proof_challenges_expiry_idx ON room_proof_challenges(expires_at);
