-- Rooms can require a university credential proof before admission. The
-- issuer key is pinned per room so a room always verifies against the
-- institution it was created for.
ALTER TABLE rooms
    ADD COLUMN credential_dept SMALLINT,
    ADD COLUMN credential_year SMALLINT,
    ADD COLUMN credential_issuer_ax TEXT,
    ADD COLUMN credential_issuer_ay TEXT,
    ADD CONSTRAINT rooms_credential_complete CHECK (
        (credential_dept IS NULL AND credential_year IS NULL
            AND credential_issuer_ax IS NULL AND credential_issuer_ay IS NULL)
        OR (credential_dept IS NOT NULL AND credential_year IS NOT NULL
            AND credential_issuer_ax IS NOT NULL AND credential_issuer_ay IS NOT NULL)
    ),
    ADD CONSTRAINT rooms_credential_range CHECK (
        credential_year IS NULL
        OR (credential_year BETWEEN 2000 AND 2100 AND credential_dept BETWEEN 1 AND 10)
    );

-- A proof may admit a membership without organizer review. The nullifier is
-- unique per room, so one credential cannot hold two seats in the same room,
-- while remaining unlinkable across rooms.
ALTER TABLE memberships
    ADD COLUMN credential_nullifier TEXT,
    ADD COLUMN credential_verified_at TIMESTAMPTZ;

CREATE UNIQUE INDEX memberships_credential_nullifier_idx
    ON memberships(room_id, credential_nullifier)
    WHERE credential_nullifier IS NOT NULL;

ALTER TABLE room_activity DROP CONSTRAINT room_activity_kind_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_kind_check CHECK (kind IN (
    'room_created', 'room_duplicated', 'room_updated', 'room_opened', 'room_closed',
    'join_requested', 'member_approved', 'member_denied', 'member_revoked',
    'key_registered', 'file_published', 'files_purged', 'credential_proved'
));

-- Credential admissions carry a participant label, and changing the gate is a
-- room metadata edit, so relax the two original activity checks.
ALTER TABLE room_activity DROP CONSTRAINT room_activity_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_check CHECK (
    (kind IN ('join_requested', 'member_approved', 'member_denied', 'member_revoked',
        'credential_proved'))
    = (member_label IS NOT NULL)
);

ALTER TABLE room_activity DROP CONSTRAINT room_activity_changed_fields_check;
ALTER TABLE room_activity ADD CONSTRAINT room_activity_changed_fields_check CHECK (
    changed_fields <@ ARRAY['title', 'description', 'expiresAt', 'credential']::TEXT[]
);
