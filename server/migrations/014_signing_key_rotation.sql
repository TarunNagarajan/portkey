CREATE TABLE platform_signing_keyring (
  kid TEXT PRIMARY KEY,
  private_pkcs8 BYTEA,
  public_spki BYTEA NOT NULL,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  verify_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CHECK ((active AND private_pkcs8 IS NOT NULL AND verify_until IS NULL) OR
         (NOT active AND private_pkcs8 IS NULL AND verify_until IS NOT NULL))
);
CREATE UNIQUE INDEX platform_signing_keyring_one_active_idx
  ON platform_signing_keyring(active) WHERE active;

INSERT INTO platform_signing_keyring(kid,private_pkcs8,public_spki,active,created_at)
SELECT kid,private_pkcs8,public_spki,TRUE,created_at FROM platform_signing_keys
WHERE singleton=TRUE;
DROP TABLE platform_signing_keys;
