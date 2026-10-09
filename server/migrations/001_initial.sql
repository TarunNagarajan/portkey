CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE TABLE rooms (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES sessions(id),
    join_code VARCHAR(16) NOT NULL UNIQUE,
    title VARCHAR(100) NOT NULL CHECK (length(trim(title)) > 0),
    description VARCHAR(500) NOT NULL DEFAULT '',
    status VARCHAR(10) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'open', 'closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL))
);

CREATE TABLE memberships (
    id UUID PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id),
    label VARCHAR(50) NOT NULL CHECK (length(trim(label)) > 0),
    status VARCHAR(10) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'revoked')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    decided_at TIMESTAMPTZ,
    UNIQUE (room_id, session_id),
    CHECK ((status = 'pending') = (decided_at IS NULL))
);

CREATE INDEX rooms_owner_idx ON rooms(owner_id);
CREATE INDEX rooms_expiry_idx ON rooms(expires_at) WHERE status <> 'closed';
CREATE INDEX memberships_session_idx ON memberships(session_id);
CREATE INDEX memberships_room_status_idx ON memberships(room_id, status);
CREATE INDEX sessions_expiry_idx ON sessions(expires_at);
