CREATE TABLE credential_groups (
  id UUID PRIMARY KEY,
  owner_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 300),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX credential_groups_owner_idx ON credential_groups(owner_session_id, created_at, id);

CREATE TABLE credential_group_invites (
  id UUID PRIMARY KEY,
  group_id UUID NOT NULL REFERENCES credential_groups(id) ON DELETE CASCADE,
  invite_number INTEGER NOT NULL CHECK (invite_number > 0),
  token_digest BYTEA NOT NULL CHECK (octet_length(token_digest) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  enrolled_commitment TEXT,
  UNIQUE(group_id, invite_number),
  UNIQUE(group_id, id),
  UNIQUE(group_id, token_digest),
  UNIQUE(group_id, enrolled_commitment),
  CHECK (enrolled_commitment IS NULL OR enrolled_commitment ~ '^[1-9][0-9]{0,76}$'),
  CHECK (revoked_at IS NULL OR enrolled_commitment IS NULL)
);

CREATE TABLE credential_group_commitments (
  group_id UUID NOT NULL REFERENCES credential_groups(id) ON DELETE CASCADE,
  commitment TEXT NOT NULL CHECK (commitment ~ '^[1-9][0-9]{0,76}$'),
  invite_id UUID NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(group_id, commitment),
  FOREIGN KEY(group_id, invite_id) REFERENCES credential_group_invites(group_id, id) ON DELETE CASCADE
);

CREATE INDEX credential_group_commitments_order_idx ON credential_group_commitments(group_id, commitment);
CREATE INDEX credential_group_invites_order_idx ON credential_group_invites(group_id, invite_number);

CREATE TABLE room_proof_groups (
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  group_id UUID NOT NULL REFERENCES credential_groups(id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
  PRIMARY KEY(room_id, group_id)
);

ALTER TABLE room_proof_challenges ADD COLUMN policy_digest TEXT;
ALTER TABLE room_proof_challenges ADD CONSTRAINT room_proof_challenges_policy_digest_check
  CHECK (policy_digest IS NULL OR policy_digest ~ '^[a-f0-9]{64}$');

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
  'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
  'join_requested', 'member_approved', 'member_denied', 'member_revoked',
  'submission_cleanup_enabled', 'submissions_purged', 'admission_passes_issued', 'pass_revoked', 'pass_redeemed',
  'proof_enrollments_issued', 'proof_enrollment_revoked', 'proof_admitted', 'proof_rule_updated', 'proof_rule_cleared'
));
