ALTER TABLE rooms ADD COLUMN admission_policy TEXT NOT NULL DEFAULT 'approval'
  CHECK (admission_policy IN ('approval', 'pass'));

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
  'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
  'join_requested', 'member_approved', 'member_denied', 'member_revoked',
  'submission_cleanup_enabled', 'submissions_purged', 'admission_passes_issued', 'pass_revoked', 'pass_redeemed'
));
ALTER TABLE room_activity DROP CONSTRAINT room_activity_changed_fields_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_changed_fields_check CHECK (
  changed_fields <@ ARRAY['title', 'description', 'expiresAt', 'admissionPolicy']::TEXT[]
);
ALTER TABLE room_activity DROP CONSTRAINT room_activity_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_check CHECK (
  (kind IN ('join_requested', 'member_approved', 'member_denied', 'member_revoked', 'pass_redeemed'))
    = (member_label IS NOT NULL)
);
CREATE TABLE room_admission_passes (
  id UUID PRIMARY KEY,
  room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  pass_number INTEGER NOT NULL CHECK (pass_number > 0),
  token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  redeemed_at TIMESTAMPTZ,
  redeemer_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
  UNIQUE (room_id, pass_number),
  CHECK (revoked_at IS NULL OR (redeemed_at IS NULL AND redeemer_session_id IS NULL)),
  CHECK (redeemer_session_id IS NULL OR redeemed_at IS NOT NULL)
);

CREATE INDEX room_admission_passes_room_idx ON room_admission_passes(room_id, pass_number);
