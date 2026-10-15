ALTER TABLE rooms
  ADD COLUMN submission_cleanup_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN submissions_purged_at TIMESTAMPTZ;

ALTER TABLE rooms ALTER COLUMN submission_cleanup_enabled SET DEFAULT TRUE;
CREATE INDEX rooms_submission_cleanup_idx
  ON rooms(expires_at, id)
  WHERE submission_cleanup_enabled AND submissions_purged_at IS NULL;

CREATE INDEX private_submissions_stale_upload_idx
  ON private_submissions(created_at, room_id, id)
  WHERE status = 'uploading';

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
  'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
  'join_requested', 'member_approved', 'member_denied', 'member_revoked',
  'submission_cleanup_enabled', 'submissions_purged'
));
