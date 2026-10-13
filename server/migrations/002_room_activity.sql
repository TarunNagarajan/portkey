CREATE TABLE room_activity (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN (
        'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
        'join_requested', 'member_approved', 'member_denied', 'member_revoked'
    )),
    member_label VARCHAR(50),
    changed_fields TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (changed_fields <@ ARRAY['title', 'description', 'expiresAt']::TEXT[]),
    CHECK ((kind IN ('join_requested', 'member_approved', 'member_denied', 'member_revoked'))
        = (member_label IS NOT NULL)),
    CHECK (member_label IS NULL OR length(trim(member_label)) > 0),
    CHECK (kind = 'room_updated' OR cardinality(changed_fields) = 0)
);

CREATE INDEX room_activity_page_idx ON room_activity(room_id, id DESC);
