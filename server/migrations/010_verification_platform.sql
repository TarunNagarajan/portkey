CREATE TABLE platform_contracts (
  id UUID PRIMARY KEY, owner_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  issuer_label TEXT NOT NULL CHECK (char_length(issuer_label) BETWEEN 1 AND 100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX platform_contracts_owner_idx ON platform_contracts(owner_session_id, created_at);

CREATE TABLE platform_contract_versions (
  contract_id UUID NOT NULL REFERENCES platform_contracts(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version > 0), description TEXT NOT NULL CHECK (char_length(description) <= 500),
  group_ids UUID[] NOT NULL CHECK (cardinality(group_ids) BETWEEN 1 AND 4),
  digest CHAR(64) NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
  adapter TEXT NOT NULL DEFAULT 'semaphore-membership-v1' CHECK (adapter = 'semaphore-membership-v1'),
  proof_depth INTEGER NOT NULL DEFAULT 10 CHECK (proof_depth = 10),
  published_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), retired_at TIMESTAMPTZ,
  PRIMARY KEY(contract_id, version)
);

CREATE TABLE platform_apps (
  id UUID PRIMARY KEY, owner_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100), origin TEXT NOT NULL,
  redirect_uris TEXT[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 3),
  key_digest BYTEA NOT NULL CHECK (octet_length(key_digest) = 32), key_generation INTEGER NOT NULL DEFAULT 1,
  disabled_at TIMESTAMPTZ, domain_challenge_digest BYTEA, domain_challenge_expires_at TIMESTAMPTZ,
  domain_verified_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(origin, id)
);
CREATE INDEX platform_apps_owner_idx ON platform_apps(owner_session_id, created_at);

CREATE TABLE platform_app_trust (
  app_id UUID NOT NULL REFERENCES platform_apps(id) ON DELETE CASCADE,
  contract_id UUID NOT NULL, contract_version INTEGER NOT NULL,
  trust_revision UUID NOT NULL DEFAULT gen_random_uuid(),
  PRIMARY KEY(app_id, contract_id, contract_version),
  FOREIGN KEY(contract_id, contract_version) REFERENCES platform_contract_versions(contract_id, version) ON DELETE CASCADE
);

CREATE TABLE platform_requests (
  id UUID PRIMARY KEY, app_id UUID NOT NULL REFERENCES platform_apps(id) ON DELETE CASCADE,
  key_generation INTEGER NOT NULL, contract_id UUID NOT NULL, contract_version INTEGER NOT NULL,
  trust_revision UUID NOT NULL,
  redirect_uri TEXT NOT NULL, state TEXT NOT NULL CHECK (state ~ '^[A-Za-z0-9_-]{43}$'), state_digest BYTEA NOT NULL CHECK (octet_length(state_digest) = 32),
  code_challenge TEXT NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  capability_digest BYTEA NOT NULL CHECK (octet_length(capability_digest) = 32),
  expires_at TIMESTAMPTZ NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','declined','exchanged')),
  wallet_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), verified_at TIMESTAMPTZ,
  code_digest BYTEA, code_expires_at TIMESTAMPTZ, code_consumed_at TIMESTAMPTZ,
  receipt_jti UUID, UNIQUE(id, app_id),
  FOREIGN KEY(contract_id, contract_version) REFERENCES platform_contract_versions(contract_id, version)
);
CREATE INDEX platform_requests_app_idx ON platform_requests(app_id, created_at DESC);
CREATE UNIQUE INDEX platform_apps_key_digest_idx ON platform_apps(key_digest);
CREATE INDEX platform_requests_expiry_idx ON platform_requests(expires_at) WHERE status = 'pending';

CREATE TABLE platform_challenges (
  id UUID PRIMARY KEY, request_id UUID NOT NULL REFERENCES platform_requests(id) ON DELETE CASCADE,
  wallet_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  accepted_root TEXT NOT NULL, scope TEXT NOT NULL, message TEXT NOT NULL,
  policy_digest CHAR(64) NOT NULL, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ,
  UNIQUE(request_id)
);
CREATE TABLE platform_nullifiers (
  request_id UUID PRIMARY KEY REFERENCES platform_requests(id) ON DELETE CASCADE,
  nullifier TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), UNIQUE(nullifier)
);
CREATE TABLE platform_signing_keys (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), kid TEXT NOT NULL UNIQUE,
  private_pkcs8 BYTEA NOT NULL, public_spki BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
