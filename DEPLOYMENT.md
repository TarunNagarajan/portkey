# Deployment and institutional operations

## Production prerequisites

Use a dedicated issuer key held by the institution, a reviewed external Groth16 ceremony for the **v2** circuit, an HTTPS domain, PostgreSQL and a backup policy. This repository cannot substitute for independent ceremony participants, an institutional identity process, physical-device acceptance testing or a third-party security review.

The default prover files intentionally remain development artifacts. Production refuses them unless `ALLOW_DEMO_CREDENTIALS=true` is explicitly set. A checksum manifest detects mixed files; a valid checksum or a successful snarkjs verification does not prove that contributors destroyed their secret entropy. Operators must review the ceremony provenance.

Import an external setup as one bundle:

```bash
ZK_PTAU=/secure/phase1.ptau \
ZK_FINAL_ZKEY=/secure/credential-final.zkey \
ZK_CEREMONY_URL=https://institution.example/ceremony/transcript \
npm run zk:build
```

The build verifies the powers-of-tau contribution chain and circuit-specific zkey with snarkjs, exports the verification key, copies prover assets and emits matching SHA-256 manifests. Keep the circuit source, ptau/zkey provenance, contribution transcript and manifest in the deployment record. Do not regenerate the default local setup for a real deployment. See the [snarkjs setup and verification instructions](https://github.com/iden3/snarkjs#readme).

## Issuance and revocation

Run the issuer CLI on an institution-controlled machine. Never put a real issuer private key in the API container, browser, Git repository or public file storage.

```bash
npx tsx scripts/issuer.ts keygen --out /secure/institution-private.json --public /secure/institution-public.json
npx tsx scripts/issuer.ts issue --key /secure/institution-private.json --dept CSE --year 2026 --expires 2027-07-01T00:00:00Z --out /secure/delivery/student.json
npx tsx scripts/issuer.ts verify --credential /secure/delivery/student.json
```

The CLI creates private files with mode 0600 and refuses to overwrite existing issuance files. Deliver each file through the institution's authenticated portal or an approved private channel. The repository does not know your student roster, delivery portal or identity-provider credentials, so connecting those remains an institution-specific integration step. Possession of the bearer credential is the current holder-authentication model.

Set `ISSUER_PUBLIC_KEY` to the public JSON. Rotation affects newly created room requirements; existing rooms keep their pinned issuer. Retain the old issuer in a controlled revocation service until its rooms expire. Every proof uses a random, session/room-specific, ten-minute challenge. Successful admission consumes it. The issuer signs the credential expiry, which the API also enforces on later room/file/key access.

A revocation is scoped to one room and does not disclose a stable cross-room credential identifier:

```bash
npx tsx scripts/issuer.ts revoke --key /secure/institution-private.json --credential /secure/delivery/student.json --room <uuid> --api https://portkey.example
```

Without `--api`, use `--out /secure/revocation.json` to create the signed request, then POST it as JSON to `/api/issuer/revocations`. The endpoint verifies the room's pinned issuer signature and atomically revokes current membership. To revoke institution-wide, the institution's revocation worker must submit the credential's separately scoped revocation for each affected room and for future rooms until the credential expires. The supplied `scripts/revocationWorker.ts` performs that one-pass delivery for every active room using the issuer key and private revoked-credential directory, and `deploy/portkey-revocation.service` / `.timer` provide a one-minute institution-side schedule. Configure `DATABASE_URL` with read-only metadata access, `ISSUER_KEY_PATH`, `REVOKED_CREDENTIALS_DIR` and `REVOCATION_API_URL` on the issuer host. The worker sends signed scoped nullifiers, never credential secrets. New rooms receive queued revocations on the next pass, so the scheduled delivery interval is a real revocation-latency boundary. Monitor failures and choose an acceptable interval. There is no global publicly linkable revocation tag. Reissuing a copied/lost credential requires revoking the old one under that policy.

## Upgrade and recovery

Migration 008 from the existing project deletes the old participant submission tables. Back up old deployments before upgrading. Migration 010 changes credential admission to v2: existing approved v1 credential memberships become pending and must use newly issued v2 credentials and fresh proofs. Denied/revoked memberships remain blocked. Old v1 credential files cannot prove against v2 artifacts.

Organizers create a one-time ownership recovery code in the room. Store it apart from the encrypted key backup. `/recover` transfers management/file authority into a fresh browser session and consumes the code. A lost code can be replaced while the organizer session remains valid; issuing a replacement invalidates the previous code. Recovery does not decrypt files, extend room expiry or erase previous downloads. The encryption backup is still required.

Migration 011 introduces a shared receiving key for all admitted members. Open each existing active room once in its organizer browser to register that key and automatically add envelopes for earlier files. Distribute the current invitation afterward. Members using an old invitation must scan the new QR once. Private receiving keys remain in invitation fragments/browser storage, never API bodies.

Optional organizer key replacement rewraps the organizer's personal file envelopes atomically. Pending uploads must finish or be discarded first. Candidate keys are retained locally before server commit, allowing reconciliation after a lost response. Download a fresh backup afterward; it includes both organizer and shared room keys. Shared student access and existing ciphertext/manifests remain unchanged.

All admitted members can download earlier and future files without the organizer being online. Revocation blocks later API reads, but cannot erase retained keys or copies. Invitation holders who obtain ciphertext separately can decrypt it. Replacing the organizer key does not rotate the shared room secret; use a new room if that secret is compromised.

## Container and HTTPS deployment

Set `POSTGRES_PASSWORD`, `APP_ORIGIN`, `ISSUER_PUBLIC_KEY`, and optionally `METRICS_TOKEN` (at least 32 random characters). Use a URL-safe database password in the supplied connection-string template. For a course demonstration only, set `ALLOW_DEMO_CREDENTIALS=true`. Then:

```bash
docker compose up --build -d
```

The API port binds to host loopback. Use `deploy/Caddyfile` with `PORTKEY_DOMAIN` and install/configure Caddy on the same host. Keep PostgreSQL on the private container network. Set `TRUST_PROXY_HOPS` only to the exact number of controlled proxy hops; do not accept arbitrary incoming forwarded IPs. The default direct server trusts zero hops; compose assumes one reverse proxy.

The image runs as the Node user, includes readiness checks and serves the built frontend. It currently retains development tooling because startup uses tsx; a separate compiled-server/minimal image can reduce footprint later. The included workflow runs build, both database backends, accessibility/browser tests, the compatibility matrix, production HTTPS proof smoke tests and the 250 MiB benchmark. CI configuration is supplied; it has not been executed by a remote GitHub runner in this session.

## Monitoring, retention and backups

`GET /api/health` checks database readiness. `GET /api/ops/metrics` requires `Authorization: Bearer <METRICS_TOKEN>` and reports encrypted byte usage, stale uploads, expired-room cleanup backlog and oldest cleanup delay. Alert when backlog or delay persists above your operational threshold. Monitor process memory, PostgreSQL disk/WAL, errors and response latency alongside these counters. A configured token is required; otherwise metrics return 404.

Rate-limit windows live in PostgreSQL and coordinate API instances. Ordinary calls use 120/minute/session, file GET/PUT chunks use 600/minute/session, and **new** sessions use 30/minute/IP. Reusing a valid cookie does not consume the creation budget. Size this policy for the institution's expected shared-network attendance before rollout.

Expiry cleanup deletes room ciphertext/envelopes/chunks in bounded batches. Incomplete uploads expire after 24 hours. Coordinates/proximity fields are cleared after 24 hours independently of room expiry. Deletion is logical database deletion, not backup or device erasure. Location claims remain spoofable and are not part of the ZKP.

Use PostgreSQL client tools to create and restore protected archives:

```bash
DATABASE_URL=<source> bash scripts/backup.sh /secure/backups/portkey.dump
RESTORE_DATABASE_URL=<new-empty-target> bash scripts/restore.sh /secure/backups/portkey.dump
```

Restore deliberately avoids destructive `--clean` operations and fails if objects already exist. Encrypt archives and define access/retention policy at the infrastructure layer. The local restore exercise verified migrated application tables and exact ciphertext bytes, not an institution's disaster-recovery RPO/RTO. Repeat scheduled restore/decryption exercises using your own backups.

Local operational probes:

```bash
TEST_DATABASE_URL=<test-postgres> npx tsx scripts/verifyLoad.ts
POSTGRES_CONTAINER=<isolated-test-container> TEST_DATABASE_URL=<test-postgres> npx tsx scripts/verifyRestore.ts
```

Both probes create isolated resources. The restore probe drops only its newly generated test databases. Never point test probes at a production database account.
