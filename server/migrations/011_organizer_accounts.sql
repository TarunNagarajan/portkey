CREATE TABLE organizer_accounts (
  id UUID PRIMARY KEY,
  user_handle BYTEA NOT NULL UNIQUE CHECK (octet_length(user_handle) BETWEEN 16 AND 64),
  owner_session_id UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE RESTRICT,
  auth_generation INTEGER NOT NULL DEFAULT 1 CHECK (auth_generation > 0),
  recovery_digest BYTEA NOT NULL CHECK (octet_length(recovery_digest) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE organizer_credentials (
  credential_id TEXT PRIMARY KEY CHECK (char_length(credential_id) BETWEEN 1 AND 1024),
  account_id UUID NOT NULL REFERENCES organizer_accounts(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 4096),
  counter BIGINT NOT NULL DEFAULT 0 CHECK (counter >= 0),
  transports TEXT[] NOT NULL DEFAULT '{}',
  device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice','multiDevice')),
  backed_up BOOLEAN NOT NULL,
  label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX organizer_credentials_account_idx ON organizer_credentials(account_id, created_at);

CREATE TABLE organizer_sessions (
  id UUID PRIMARY KEY,
  account_id UUID NOT NULL REFERENCES organizer_accounts(id) ON DELETE CASCADE,
  token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
  auth_generation INTEGER NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  verified_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX organizer_sessions_account_idx ON organizer_sessions(account_id, expires_at);

CREATE TABLE organizer_ceremonies (
  id UUID PRIMARY KEY,
  challenge TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('signup','login','recovery','reauth','add_passkey','remove_passkey','rotate_recovery','revoke_sessions')),
  browser_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  account_id UUID REFERENCES organizer_accounts(id) ON DELETE CASCADE,
  organizer_session_id UUID REFERENCES organizer_sessions(id) ON DELETE CASCADE,
  auth_generation INTEGER,
  recovery_digest BYTEA,
  prospective_account_id UUID,
  prospective_user_handle BYTEA,
  target_credential_id TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((kind = 'signup' AND prospective_account_id IS NOT NULL AND prospective_user_handle IS NOT NULL) OR kind <> 'signup')
);
CREATE INDEX organizer_ceremonies_browser_idx ON organizer_ceremonies(browser_session_id, expires_at);

CREATE VIEW owner_authorities AS
  SELECT s.id, a.id AS account_id, (a.id IS NOT NULL OR s.expires_at > clock_timestamp()) AS available,
         CASE WHEN a.id IS NULL THEN s.expires_at ELSE NULL::timestamptz END AS expires_at
    FROM sessions s LEFT JOIN organizer_accounts a ON a.owner_session_id = s.id;
