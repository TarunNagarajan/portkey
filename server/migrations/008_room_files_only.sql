DROP TABLE submission_chunks;
DROP TABLE submission_envelopes;
DROP TABLE private_submissions;

ALTER TABLE rooms
  DROP COLUMN submission_cleanup_enabled,
  DROP COLUMN submissions_purged_at,
  ADD COLUMN files_purged_at TIMESTAMPTZ;

DROP INDEX IF EXISTS rooms_submission_cleanup_idx;
CREATE INDEX rooms_files_cleanup_idx
  ON rooms(expires_at, id)
  WHERE files_purged_at IS NULL;

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
    'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
    'join_requested', 'member_approved', 'member_denied', 'member_revoked',
    'key_registered', 'file_published', 'files_purged'
));
