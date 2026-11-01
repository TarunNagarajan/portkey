# Portkey

A temporary-room file-sharing platform built with React, TypeScript, Express and PostgreSQL/PGlite. Organizers distribute browser-encrypted files to approved participants. Optional Groth16 credential proofs admit eligible students without sending their credential secret, signature, name or roll number to the API.

## Run

Use Node.js 22.12 or newer:

```bash
npm ci
npm run dev
```

Open http://localhost:5173. The API listens on 127.0.0.1:3001. Defaults work without `.env`; copy `.env.example` to customize them. PGlite persists data under `.data/portkey`. Set `DATABASE_URL` for PostgreSQL. Startup applies numbered migrations and checks their checksums; never edit an applied migration.

`APP_ORIGIN` must exactly match the browser origin. Set `API_ORIGIN` to change the Vite proxy target. `GEOCODING=false` disables Nominatim place lookup. `HOST` defaults to `127.0.0.1`; containers can use `HOST=0.0.0.0` behind an appropriate proxy.

For production, build with `npm run build`, use `NODE_ENV=production`, an HTTPS `APP_ORIGIN`, and an explicit `ISSUER_PUBLIC_KEY`, then run `npm start` behind an HTTPS reverse proxy. `ALLOW_DEMO_CREDENTIALS=true` explicitly permits the bundled development issuer for a course demo. An explicit issuer configuration does **not** replace the development Groth16 trusted setup: production proof trust still requires independently reviewed ceremony artifacts.

For phone testing, `npm run share` builds the app and starts a public Cloudflare quick tunnel. It requires `cloudflared` on PATH, uses HTTPS and explicitly opts into demo credentials unless overridden. Stop with Ctrl+C. Treat this as a public course demo, not an institutional deployment.

## Room workflow

1. Create a draft with a title, description and future expiry, at most seven days away.
2. Optionally require a department/class-year credential and/or set a circular geographic area.
3. Open the room. Encryption is prepared automatically.
4. Share the QR/invitation through a trusted channel. Its fragment includes the room access secret; do not publish it openly.
5. Participants request access with a self-chosen label. The organizer approves them, or a matching credential proof admits them automatically.
6. Publish files at any time. Every admitted member can download earlier and future publications, even if the organizer browser is closed. Download verifies and decrypts the file automatically.

Fingerprints, encrypted key backups and organizer key replacement are under **Security and recovery (optional)**. Organizers should save a protected backup for recovery.

Rooms transition from draft to open to closed; expiry is enforced by the database clock independently of the cleanup worker. Closed/expired rooms cannot reopen. Owners can inspect room metadata and activity afterward; file access ends at closure/expiry. Templates create fresh drafts with new invitations and no memberships. Search/filter works in the workspace.

Ownership and membership are tied to a 30-day HttpOnly browser session. Clearing cookies loses authorization. An encrypted key backup recovers only the encryption key, not the session or room ownership. Organizers can create a separate one-time ownership recovery code and redeem it at `/recover`. Recovery transfers authorization; the encrypted key backup separately restores decryption. Co-host roles are not part of this implementation.

The current product distributes files **organizer → participants**. Participant uploads/private submissions were removed. Migration `008_room_files_only.sql` drops the historical submission tables and their data. Back up an older deployment before upgrading; its old inbox contents are not migrated to room files.

## Encryption and file limits

The browser encrypts filenames/metadata and file contents using AES-256-GCM. Each file has a fresh secret and salt, separate HKDF-SHA256 content/metadata keys, and indexed chunk nonces. HPKE P-256/HKDF-SHA256/AES-256-GCM wraps each file key for the organizer and the shared room receiving key. Authenticated contexts bind the room, file, recipient and purpose. Server storage contains ciphertext, recipient envelopes, sizes and acceptance receipts; it cannot read file names or contents through the normal protocol.

Chunk retries must contain identical ciphertext. Completion checks a SHA-256 manifest of the encrypted descriptor and ordered chunk hashes. Downloads authenticate chunks and the complete manifest before saving plaintext. The receipt records server acceptance; it is not an independently signed attestation.

Limits: 250 MiB per file, 250 chunks of up to 1 MiB plaintext, 1,000 files and 5 GiB encrypted chunk storage per room, at most 20 incomplete uploads. Capacity is checked under the room lock as chunks arrive rather than reserving a full file upfront. Metadata/envelopes also have bounded payloads. Failed/cancelled browser uploads attempt to delete their incomplete server record; inaccessible/disconnected attempts are reclaimed after 24 hours. Upload plans and immutable ciphertext chunks survive reloads in IndexedDB. The original source snapshot lives in OPFS, or a bounded 50 MiB ArrayBuffer fallback. Resume never re-encrypts an already reserved index: if a crash lost ciphertext after reservation, discard and start with a fresh file key. Failed network transfers keep their local journal and can be resumed; discard removes it. Browser eviction can still remove local state.

All admitted members use a shared room receiving key carried in the trusted invitation fragment. The private key stays in browsers; the API stores its public key and encrypted file-key envelopes. Admission, credential validity, geographic checks, revocation and room expiry still gate every file API request. New members can read earlier publications without an online organizer. Removing access blocks future requests, but cannot retract ciphertext, keys or plaintext already downloaded. Anyone with the invitation secret and a separately obtained ciphertext copy can decrypt that copy: this design intentionally gives admitted members equal file access, rather than individual cryptographic isolation.

Invitation fragments are not sent in HTTP requests. The browser validates the invitation key against the room's registered public fingerprint silently. A fingerprint identifies a key; it is not independently verified institutional identity.

Private keys live in IndexedDB. Optional organizer key replacement atomically rewraps the organizer's personal envelopes and requires pending uploads to finish or be discarded first. It preserves the shared room key and student access; it does not revoke a leaked room secret. Candidate keys are saved before server commit so a lost response can be reconciled. Export a fresh organizer backup afterward. Encrypted backups use PBKDF2-HMAC-SHA256 (600,000 iterations), a random salt and AES-256-GCM. Organizer backups include the room receiving key; restoration validates the room, registered fingerprints and keypairs. The browser clears the passphrase after successful export/restore.

Migration 011 adds shared room access. Open an existing active room once in its organizer browser to upgrade earlier files automatically, then distribute its current invitation. No ciphertext is re-uploaded. Legacy individual-envelope APIs remain compatible until that upgrade. An original organizer backup can derive the initial room receiving key; after organizer key replacement use the latest backup.

Downloads use Origin Private File System staging when available. Save-file-picker downloads remove staging after saving; fallback downloads retain their temporary source until “Remove local download copies” is used (at most five retained copies). Without OPFS, memory downloads are limited to 50 MiB. Browser/device compromise can expose private keys and local plaintext.

## Location restrictions

Areas range from 50 metres to 50 kilometres. An area can change on an active room until anyone has been admitted; revocation does not unlock it. Place lookup supplies a center/label, not an authorization decision.

Joining requires a fresh location with accuracy at most 75 m. The browser watches for up to 20 seconds so an initial coarse network location can improve. If it remains inaccurate, the app explains the reported uncertainty and asks the participant to enable precise location and retry near a window or outdoors; it does not reduce the admission accuracy requirement. Participant room entry, encryption-key registration, key retrieval, file lists and every ciphertext chunk require an inside location checked within five minutes, using the database clock. Owners are exempt. Participants can refresh with `POST /api/rooms/:id/position`. The browser room page refreshes stale fixes on demand.

Location is self-reported by the browser and can be spoofed; this is not cryptographic proof of physical presence. Coordinates reach the server and appear as proximity information for the organizer. Cleanup clears stored proximity fields after 24 hours. `GEO_STALE`, `GEO_OUTSIDE`, `GEO_REQUIRED` and `GEO_INACCURATE` explain rejected fixes.

## Zero-knowledge credential gate

The v2 issuer signs `Poseidon(secret, department, year, validUntil)` using EdDSA BabyJubjub/Poseidon. The browser proves signature possession and the required public attributes with the committed Circom/Groth16 artifacts. Only the proof and nine public signals reach the API: nullifier, session binding, issuer coordinates, department, year, room scope, challenge and signed expiry. The random ten-minute challenge belongs to one room/session and is consumed transactionally on successful admission. The circuit binds it through `Poseidon(secret, challenge)`, independently of the stable per-room nullifier. Verification binds every public signal to the room's pinned requirement.

The per-room nullifier `Poseidon(secret, roomScope(roomId))` enforces one credential per room across browser sessions. Revoking access does not release that credential's seat. Nullifiers differ across rooms, but browser sessions, network addresses and timing still permit correlation. The credential file is a bearer secret; someone who copies it can impersonate its holder subject to the one-seat rule. A copied proof fails in another browser session or after the challenge is consumed. The signed expiry continues to apply to already-admitted room and file access.

Admission rules freeze after the first admission, including after revocation. If a gate is added while requests are pending, those participants must prove their credentials; manual approval cannot bypass the gate.

Demo commands:

```bash
npm run zk:issue -- --dept CSE --year 2026 --out credentials/student1.json
npx tsx scripts/issuer.ts verify --credential credentials/student1.json
npm run zk:prove -- --credential credentials/student1.json --room <room-uuid> --challenge <challenge-from-api>
```

Generated credentials default to `credentials/credential-<DEPT>-<YEAR>.json` when `--out` is omitted. Parent folders are created automatically. The `credentials/` folder is excluded from Git and Docker builds; use a distinct filename for each student. Existing files are never overwritten.

`npx tsx scripts/issuer.ts keygen --out <private-key-path> --public <public-key-path>` generates an issuer. Keep its private file outside the repository and configure the API with the public JSON via `ISSUER_PUBLIC_KEY`. Existing rooms retain their pinned issuer. The bundled `fixtures/dev-issuer.json` is public: anyone can mint demo credentials. `npm run zk:build` regenerates all prover/verifier artifacts together using a **development-only** setup. It is not a multi-party ceremony.

The issuer CLI supports signed expiry and signed room-scoped revocations through `/api/issuer/revocations`. The supplied institution-side revocation worker and timer apply scoped revocations across active and newly created rooms. Institutions must connect private issuance/delivery and the worker to their actual roster/portal and accept the scheduled delivery latency. The server rejects development ceremony artifacts and the known demo issuer in production unless demo mode is explicit. External ceremony import verifies the contribution chain and circuit match and emits checked hash manifests. No independent security audit or actual institutional ceremony has been performed. See [DEPLOYMENT.md](DEPLOYMENT.md) for the operator workflow.

## Retention, activity and access

At room expiry, a cleanup pass deletes all room files, envelopes and chunks and sets `files_purged_at`. Cleanup runs at startup and roughly every minute with bounded batches; backlog/downtime can delay physical deletion. Closing early blocks access but does not purge before expiry. Stale incomplete uploads are removed after 24 hours. This is logical deletion in the active database, not erasure of backups or downloaded copies.

Organizer-only activity records lifecycle, membership, credential admission, key registration, publication and cleanup. Action/history writes commit together. `GET /api/rooms/:id/activity?before=<cursor>` returns up to 20 events. The UI polls every five seconds and supports older pages. This is an operational history, not a tamper-proof log.

Writes require the configured Origin and session-derived `X-CSRF-Token`. Cookies use HttpOnly/SameSite=Strict and Secure/`__Host-` in production. API responses use `no-store`. PostgreSQL-backed atomic windows coordinate limits across API instances: ordinary requests allow 120/minute/session, file chunk requests have a separate 600/minute/session budget, and new session creation is bounded to 30/minute/IP to prevent resetting budgets by requesting fresh cookies. Reusing a valid session does not consume the creation budget. Set `TRUST_PROXY_HOPS` only for a controlled proxy path; zero hops are trusted by default.

A server serving malicious JavaScript can steal browser plaintext, private keys and credential secrets. Room metadata, labels, sizes, timing, membership relationships and network addresses are not concealed. The protocol does not prevent copying downloaded files.

## API map

All endpoints are under `/api`. Start/reuse a session with `POST /session`; preserve the cookie and use the returned CSRF token on writes. Errors contain `{ error: { code, message } }`.

| Endpoint | Operations |
| --- | --- |
| `/health`, `/session` | GET readiness; POST session |
| `/rooms` | GET workspace; POST draft |
| `/rooms/:id` | GET authorized room; PATCH metadata |
| `/rooms/:id/duplicate` | POST fresh owner-only draft |
| `/rooms/:id/open`, `/rooms/:id/close` | POST lifecycle transition |
| `/join/:code` | GET public details/own status; POST request/proof |
| `/rooms/:id/credential` | PUT requirement; DELETE gate before first admission |
| `/geo/search`, `/rooms/:id/geo` | GET place search; POST/DELETE area before first admission |
| `/rooms/:id/position` | POST fresh participant location |
| `/rooms/:id/members`, `/rooms/:id/members/:memberId` | GET owner list; PATCH admission decision |
| `/rooms/:id/activity` | GET owner history with optional `before` |
| `/rooms/:id/keys/owner`, `/rooms/:id/keys/participant` | POST immutable public key |
| `/rooms/:id/keys/room-access` | POST immutable shared room public key (owner only) |
| `/rooms/:id/files/room-access` | POST shared envelopes for earlier publications (owner only) |
| `/rooms/:id/files/keys` | GET authorized recipient key information |
| `/rooms/:id/files` | POST owner upload with `fileId`; GET authorized list with optional `before` |
| `/rooms/:id/files/:fileId/metadata` | PUT encrypted descriptor/envelopes |
| `/rooms/:id/files/:fileId/chunks/:index` | PUT owner ciphertext; GET authorized ciphertext |
| `/rooms/:id/files/:fileId/complete` | POST chunk count/manifest |
| `/rooms/:id/files/:fileId` | DELETE owner upload or published file; `?incompleteOnly=true` restricts cleanup to incomplete attempts |
| `/join/:code/challenge` | POST a ten-minute proof challenge for this browser session |
| `/issuer/revocations` | POST an issuer-signed room/nullifier revocation |
| `/rooms/:id/keys/rotate` | POST replacement key and every existing file envelope |
| `/rooms/:id/files/grants` | POST organizer-authorized earlier-file envelopes |
| `/rooms/:id/recovery`, `/rooms/recover` | POST create/rotate code; POST redeem once |
| `/rooms/:id/files/:fileId/upload` | GET owner upload/chunk progress |
| `/ops/metrics` | GET token-protected backlog/storage metrics |

## Verification and remaining work

```bash
npm test
npm run build
npx playwright install chromium
npm run test:e2e
npm run test:compat
npm run test:production
npm run test:large
```

API tests use an isolated embedded database, including real credential proofs, authorization, retention, quotas and rate-limit regressions. Browser tests start isolated servers (main suite 3002/5174, compatibility 3004/5175, large-file 3005/5176, HTTPS smoke 3003/5443) and generate real proofs, perform encrypted file transfers and test organizer/participant backup restoration. Their persistent test data is separate from the development database; screenshots go to `../outputs`.

See [AUDIT.md](AUDIT.md) for fixes, validation and prioritized remaining work. The original completion-snapshot report and presentation PDFs live under `docs/` and the parent workspace `../docs`. Their generator and evidence sources are versioned; use this README and `docs/CODE_GUIDE.md` for the later automatic-access changes. The 250 MiB benchmark, load probe and restore evidence live under `benchmark-results/`.

## Upgrade note

Credential protocol v2 requires newly issued v2 credentials and coordinated prover/verifier assets. Migration 010 returns approved legacy v1 credential admissions to pending so they can prove again; denied/revoked browsers remain blocked. Back up before applying migrations. Browser private storage is not included in server backups. Participant uploads remain excluded.

For the presentation, see [docs/CODE_GUIDE.md](docs/CODE_GUIDE.md) for the custom source-file inventory, code walkthrough and library boundaries.
