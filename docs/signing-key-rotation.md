# Platform receipt signing key rotation

Portkey signs platform verification receipts with an Ed25519 key held in the platform database. Rotation is an operator action; room organizers and relying applications have no key management endpoint or credential.

For PostgreSQL, run `npm run signing-keys:rotate` from an operator environment configured with `DATABASE_URL`. The command applies pending migrations and atomically activates a newly generated key. It does not print key material. Retired private material is removed in the same transaction. The retired public key remains in the JWKS for ten minutes so receipts issued immediately before rotation can be verified; it is then omitted from JWKS.

Embedded databases require an explicit offline action because the running app cannot safely share its PGlite data directory with a second process. Stop the local Portkey server, then run `npm run signing-keys:rotate -- --offline-embedded`. Without this flag, the command refuses to open an embedded database. The flag is rejected when `DATABASE_URL` is set.

JWKS holds at most eight active or still-valid retired keys. Rotations also have a 60-second cooldown. If a rotation is too soon or the JWKS capacity is full, the command fails with a clear error; wait and retry. Rotation, first-key initialization, and receipt signing coordinate through a PostgreSQL transaction advisory lock, so concurrent operators and API instances cannot activate multiple keys or sign using a key after it has been retired.

The SDK caches JWKS for up to one minute and coalesces concurrent fetches per origin. When a receipt names an unknown key, it refreshes JWKS once and retries key selection. Unknown-key refreshes are limited to one per origin each second, including repeated invalid-kid attempts. A known key with an invalid signature is rejected without a refresh. Verification continues to use the configured Portkey origin; receipt data cannot nominate a key server.
