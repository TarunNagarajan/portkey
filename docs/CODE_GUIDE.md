# Portkey code guide for the presentation

All paths below are relative to the `portkey/` application folder. This guide identifies the project's custom code and configuration. It does not claim that we invented the cryptographic algorithms or wrote the third-party libraries.

## 1. What is our project code?

| Folder / file | Classification | What to explain |
| --- | --- | --- |
| `client/` | Custom application source | React pages, browser encryption, proof generation, location and upload retry state |
| `server/` | Custom application source | Express API, authorization, PostgreSQL queries, proof checks and cleanup |
| `shared/` | Custom application source | Types, input schemas and rules shared between browser and API |
| `circuits/credential.circom` | Custom ZKP circuit | Which signed facts a holder must prove and how room/session binding works |
| `circuits/build.mjs` | Custom build script | Compile the circuit and prepare/import the matching proof artifacts |
| `scripts/` | Custom project tooling | Issuing credentials, sharing the demo, operating and measuring the platform |
| `tests/`, `e2e/` | Custom test code | Evidence that the rules work and regressions stay fixed |
| Root/deployment configuration | Project configuration, some based on normal framework conventions | How we build, run, test and deploy the application |
| `docs/`, `README.md`, `AUDIT.md`, `DEPLOYMENT.md` | Project documentation | Design, implementation, limitations and verification evidence |

These are the files to study and explain. You do not need to explain the internals of every installed package.

## 2. Files to explain first

For a short code walkthrough, use this order:

| Order | File | Presentation point |
| --- | --- | --- |
| 1 | `client/main.tsx` | React entry point. Starts a session and chooses workspace, join, room or recovery page from the URL. |
| 2 | `server/index.ts` | API entry point. Opens the database, applies migrations, starts cleanup, serves the production frontend and listens for requests. |
| 3 | `server/app.ts` | Wires middleware and routes: security headers, body limits, session loading, rate limits, Origin/CSRF checks and errors. |
| 4 | `shared/rooms.ts` | A single contract for room inputs, lifecycle types, join requests and location validation. |
| 5 | `server/rooms.ts` | Core room business logic: create, open, join, approve, revoke, close, credential challenges and geographic rules. |
| 6 | `client/JoinPage.tsx` | Student flow: label, optional credential selection, location, challenge, proof and access request. |
| 7 | `circuits/credential.circom` | The actual zero-knowledge statement. Point out public inputs, private inputs, signature verification, nullifier and challenge binding. |
| 8 | `server/zk.ts` | Verifies the proof and matches its public signals to the room's pinned issuer and eligibility rule. |
| 9 | `client/roomCrypto.ts` | Browser content encryption, HPKE file-key envelopes, authenticated downloads and encrypted key backups. |
| 10 | `client/RoomFiles.tsx` and `server/roomFiles.ts` | Connect encrypted file-sharing UI to owner-only publication, recipient reads, quotas and manifest checks. |
| 11 | `server/database.ts` and `server/migrations/` | Persistent storage, transactions, constraints and schema evolution. |
| 12 | `client/uploadStore.ts` | Safe resume: reserve an encryption index, save its immutable ciphertext, then upload. |

Start with the feature and follow its data through these files. A line-by-line tour of every file is unnecessary.

## 3. Browser source: client/

| File | Responsibility |
| --- | --- |
| `main.tsx` | React bootstrapping, initial browser session, URL-based page selection, navigation and offline notice. |
| `Home.tsx` | Workspace room list, search/status filters, creation and template selection. |
| `RoomForm.tsx` | Room title, description, deadline and optional credential requirement form. |
| `RoomPage.tsx` | Room overview, polling, owner actions, admission decisions and participant access state. |
| `JoinPage.tsx` | Student label, credential input, optional location and admission/proof submission. |
| `ShareRoom.tsx` | Invitation link and QR code, including the private room access fragment and organizer fingerprint. Uses the qrcode library to render the QR. |
| `RoomFiles.tsx` | Automatic encryption setup, publication/resume, shared access, downloads and optional recovery controls. |
| `roomCrypto.ts` | Integrates Web Crypto and HPKE for key generation, encryption, descriptors, envelopes, manifest verification, OPFS staging and key backups. |
| `uploadStore.ts` | IndexedDB upload journal, immutable ciphertext reservations and locally retained source snapshots. |
| `credentialProof.ts` | Parses credential JSON, checks it against room attributes and invokes SnarkJS to generate a proof. |
| `RoomCredential.tsx` | Organizer controls to configure the accepted department/class year before admissions lock the rule. |
| `RoomArea.tsx` | Organizer area search, device-based center selection and radius configuration. |
| `location.ts` | Watches for a fresh precise location instead of immediately submitting a coarse phone fix. Stops the watch on success, denial or timeout. |
| `api.ts` | JSON/binary HTTP helpers, CSRF handling, browser session setup and readable network/API errors. Re-exports location access. |
| `ActivityLog.tsx` | Organizer-only event timeline, polling, cursor pagination and retry controls. |
| `Recovery.tsx` | Owner recovery-code creation and the separate ownership recovery form. |
| `ui.tsx` | Reusable icons, branding, status badges, deadline display and formatting. |
| `styles.css` | Custom layout, typography, colors, responsive behavior, focus treatment and reduced-motion rules. |

`location.ts` was added to fix the phone issue: a coarse network reading can improve while GPS warms up. The join/entry accuracy requirement is still 75 metres. Owner area-center selection uses a separate, looser acquisition target; it does not change student admission rules.

## 4. API and database source: server/

| File | Responsibility |
| --- | --- |
| `index.ts` | Process startup, database/migrations, cleanup scheduler, production static serving and shutdown. |
| `app.ts` | Express middleware, routes, input/error handling and security boundaries. |
| `config.ts` | Environment validation: origin, port, database, geocoding, issuer, demo mode, metrics and proxy hops. |
| `sessions.ts` | Random HttpOnly session cookies, stored token hashes, session expiry, Origin checks and CSRF validation. |
| `rooms.ts` | Room lifecycle, membership transitions, location reports, proof challenges and auto-admission. |
| `participantAccess.ts` | Shared participant authorization for room, file and key APIs, including credential activity and recent inside-location checks. |
| `keys.ts` | Owner and shared-room public-key registration, plus atomic organizer rotation. |
| `roomFiles.ts` | Owner uploads, metadata/envelopes, chunks, immutable retries, completion manifests, authorized listing/reads, automatic shared envelopes for earlier files and deletion. |
| `zk.ts` | Issuer loading, artifact checksums, production setup safeguards and Groth16 public-signal/proof verification. |
| `issuerRoutes.ts` | Verifies issuer signatures on room-scoped revocations and invalidates matching membership. |
| `recovery.ts` | Stores hashed one-time ownership codes and transfers ownership/file authority on successful redemption. |
| `database.ts` | Common query/transaction interface over PGlite or a PostgreSQL connection pool. Uses parameterized SQL. |
| `migrations.ts` | Applies numbered SQL migrations transactionally and checks migration checksums. |
| `migrate.ts` | Command-line migration entry point used by `npm run db:migrate`. |
| `activity.ts` | Transactional activity insertion and newest-first cursor pagination. |
| `cleanup.ts` | Expired-room file purge, cleanup scheduling, expired challenge/rate-window removal and proximity retention. |
| `staleUploads.ts` | Reclaims incomplete uploads older than 24 hours and reports reclaimed usage. |
| `geocoding.ts` | Place search/reverse lookup through Nominatim, with timeout and disabled-mode handling. |
| `rateStore.ts` | PostgreSQL-backed atomic rate windows shared across API instances. |
| `operations.ts` | Token-protected storage and cleanup-backlog metrics. |
| `errors.ts` | Consistent HTTP error class and reusable precondition checks. |

### SQL migration files we maintain

| File | Purpose |
| --- | --- |
| `001_initial.sql` | Sessions, rooms, memberships, lifecycle and relational constraints. |
| `002_room_activity.sql` | Organizer activity/history storage. |
| `003_private_submissions.sql` | Historical private-submission tables and recipient-key tables. Recipient-key tables remain in use. |
| `004_submission_limits.sql` | Historical submission limits. |
| `005_submission_retention.sql` | Historical submission retention settings. |
| `006_geofence.sql` | Room area and membership proximity columns. |
| `007_room_files.sql` | Organizer-to-room encrypted file distribution tables. |
| `008_room_files_only.sql` | Removes historical submission data structures and establishes file-purge tracking. |
| `009_credential_proofs.sql` | Room credential requirements, pinned issuer and per-room nullifier uniqueness. |
| `011_room_wide_access.sql` | Shared public receiving keys and shared encrypted file-key envelopes; no private key storage. |
| `010_hardening.sql` | Proof challenges, credential expiry/revocations, ownership recovery, shared request budgets and associated indexes. |

Files 003-005 record earlier development history. They do not mean the current app still supports participant uploads. Explain migrations as schema evolution, not as separate active features.

## 5. Shared code and the circuit

| File | Responsibility |
| --- | --- |
| `shared/rooms.ts` | Room/member types, Zod API schemas and common location/radius limits. |
| `shared/credentials.ts` | Credential v2 schema, attribute definitions, field parsing, signed commitment, room scope, nullifier and circuit-input mapping. |
| `shared/geo.ts` | Great-circle distance, inside-area checks, radius helpers and readable location-accuracy guidance. |
| `shared/activity.ts` | Event names, changed-field names and timeline response types. |
| `circuits/credential.circom` | Our constraint wiring for eligibility: EdDSA signature over the signed commitment, range checks, per-room nullifier and session challenge binding. Imports cryptographic circuit components from circomlib. |
| `circuits/build.mjs` | Compiles with circom2, creates development artifacts or verifies/imports an external ceremony, and exports matching assets/manifests. |
| `types/snarkjs.d.ts` | Local TypeScript declarations describing the SnarkJS APIs we call. This is type glue, not a proof implementation. |

### The ZKP statement to explain

“The presenter knows a secret and issuer signature for the required department/year and signed expiry. The proof is for this room and fresh browser challenge. A stable per-room nullifier prevents the same credential taking another seat.”

Private inputs: credential secret and signature. Public signals: nullifier, challenge binding, issuer coordinates, department, year, room scope, challenge and expiry.

The credential JSON is selected in the browser; the normal join API receives the proof and public signals, not the original secret/signature. Issuer tooling is a separate role that creates or holds the credential for issuance/revocation operations.

## 6. Custom tooling: scripts/

| File | Responsibility |
| --- | --- |
| `issuer.ts` | CLI to generate issuer keys, issue/verify credentials and sign/send scoped revocations. Generated student files default to `credentials/`. |
| `issuerLib.ts` | Integrates issuer key generation, Poseidon commitments, EdDSA signing and credential/revocation verification. |
| `proveCredential.ts` | Generates a credential proof from a local file and room challenge outside the browser. Used in API tests and debugging. |
| `revocationWorker.ts` | Institution-side one-pass worker: reads private revoked credentials and delivers signed scoped revocations for active rooms. |
| `revocationWorkerLib.ts` | Testable idempotent delivery logic, including newly created rooms. |
| `share.mjs` | Builds the app, launches a Cloudflare HTTPS tunnel and starts the API with its public origin. For laptop/phone demonstrations. |
| `productionProxy.mjs` | Local HTTPS test harness with a temporary certificate and production-mode API. Not the live deployment proxy. |
| `backup.sh` | Creates a protected PostgreSQL archive and checks its archive listing. |
| `restore.sh` | Restores into a new empty database without destructive clean/drop options. |
| `verifyLoad.ts` | Isolated two-instance PostgreSQL rate-budget probe. |
| `verifyRestore.ts` | Isolated PostgreSQL backup/restore exercise with exact ciphertext-byte checks. |
| `artifactManifest.mjs` | Development helper to record checksums for existing local ZKP build artifacts. Not an independent ceremony or audit. |
| `buildDocs.py` | Generates the project report and presentation PDFs from screenshots and saved evidence. |

## 7. Custom tests

### API / utility tests

| File | Covers |
| --- | --- |
| `tests/rooms.test.ts` | Sessions, CSRF, lifecycle, approval, templates, persistence and transactional history. |
| `tests/geo.test.ts` | Distance/area rules, stale/inaccurate reports, room entry and readable coarse-phone errors. |
| `tests/location.test.ts` | Coarse-to-precise readings, keeping a measurement intact, timeout guidance, permission denial and GPS-watch cleanup. |
| `tests/hpke.test.ts` | HPKE interoperability against a published RFC test vector. The vector is external evidence, not an algorithm we invented. |
| `tests/credentials.test.ts` | Real proof verification, room/issuer/session binding, nullifier reuse, expiry and revocation worker behavior. |
| `tests/room-files.test.ts` | File/key authorization, quotas, retries, manifest integrity, retention, grants, rotation, recovery and shared budgets. |
| `tests/config.test.ts` | Production issuer configuration/demo-mode requirements. |
| `tests/operations.test.ts` | Protected metrics, cleanup backlog and proximity retention. |
| `tests/database.ts` | Test database setup, including isolated PostgreSQL schemas and cleanup. |

### Browser tests

| File | Covers |
| --- | --- |
| `e2e/room-flow.spec.ts` | Organizer/student workflow, encrypted transfer, key backups, resume, integrity, workspace and activity. |
| `e2e/credential.spec.ts` | Real in-browser proofs, one-seat enforcement and pending-request proof upgrades. |
| `e2e/geofence.spec.ts` | Organizer area setup and precise/coarse/outside student location behavior. |
| `e2e/key-lifecycle.spec.ts` | Automatic access for late arrivals, organizer key replacement and recovered ownership/decryption. |
| `e2e/resilience.spec.ts` | Offline state, unavailable private storage, quota errors and interrupted encryption reservations. |
| `e2e/accessibility.spec.ts` | Keyboard and automated accessibility checks. |
| `e2e/compatibility.spec.ts` | Browser encryption, storage, recovery and keyboard checks across browser engines. |
| `e2e/large-file.spec.ts` | Actual 250 MiB upload/download, byte verification and staging cleanup. |

## 8. Configuration and deployment files

| File | Responsibility |
| --- | --- |
| `package.json` | Our dependency declarations and commands (`dev`, `share`, `build`, tests and ZKP tools). |
| `package-lock.json` | Package-manager-generated exact dependency resolution. Do not present it as application logic. |
| `index.html` | HTML entry document that mounts the React application. |
| `tsconfig.json` | Strict TypeScript and JSX compiler settings. |
| `vite.config.ts` | React build, local frontend server and API proxy configuration. |
| `playwright.config.ts` | Main browser test servers and defaults. |
| `playwright.compat.config.ts` | Chromium/Firefox/WebKit test matrix. |
| `playwright.large.config.ts` | Isolated servers and longer timeout for the large-file test. |
| `playwright.production.config.ts` | Built-app HTTPS/CSP/secure-cookie test setup. |
| `.env.example` | Documented environment-variable template. Actual `.env` contains local settings and is ignored by Git. |
| `.gitignore`, `.dockerignore` | Prevent runtime files, private credentials and dependencies entering Git or the image context. |
| `Dockerfile` | Application build and non-root runtime image with a readiness check. |
| `compose.yaml` | API/PostgreSQL services, persistence, readiness and environment wiring. |
| `.github/workflows/verify.yml` | CI verification steps. Supplied workflow is not evidence that remote CI already ran. |
| `deploy/Caddyfile` | Intended production HTTPS reverse-proxy configuration. |
| `deploy/portkey-revocation.service`, `deploy/portkey-revocation.timer` | Institution-side scheduled revocation delivery. Requires actual issuer configuration outside the app container. |

## 9. Files and folders that are NOT handwritten application logic

| Location | What it actually is |
| --- | --- |
| `node_modules/` | Installed third-party libraries. Do not explain or edit their source as our implementation. |
| `dist/` | Generated production frontend, compiled/minified from our source and dependencies. |
| `circuits/build/` | Generated intermediate circuit/setup files. |
| `public/zk/credential.wasm`, `public/zk/credential.zkey` | Generated proving assets derived from our circuit/setup. They are needed at runtime but are not handwritten source files. |
| `server/zk/verification_key.json` | Generated Groth16 verification data used by our verifier integration. |
| `public/zk/manifest.json`, `server/zk/manifest.json` | Generated artifact metadata/checksums. A checksum is not a ceremony security audit. |
| `fixtures/dev-issuer.json`, `server/zk/issuer.json` | Demo issuer key data. Generated fixtures, not student identity records or production trust roots. |
| `credentials/` | Private generated student credential files. Ignore in Git/Docker; do not display secrets or share one file with an entire class. |
| `.data/` | Runtime local database contents. |
| `test-results/`, `playwright-report/`, `coverage/` | Generated test evidence. |
| `benchmark-results/` | Measured result JSON files from our probes. |
| `public/photos/` | Third-party photographs/video used in the interface. Credit their creators via `credits.json`; do not claim we created those photographs. |
| `.taste-skill/` | Design inspection artifacts from development, not required runtime code. |
| `docs/*.pdf`, parent `../docs/`, `../outputs/` | Generated report/presentation PDFs and application screenshots. |
| `.git/` | Repository metadata. |

## 10. What we use libraries for

| Library / platform | Its part | Our part |
| --- | --- | --- |
| React / React DOM | Component rendering and state hooks | Pages, forms, state transitions and workflow |
| Express | HTTP server/router framework | API endpoints, policies and business logic |
| Zod | Schema validation engine | The actual schemas and allowed values |
| PostgreSQL / PGlite / pg | Database engine and driver | Table design, migrations, queries and transaction boundaries |
| @noble/curves | P-256 public-point derivation from a private scalar across browsers | Deterministic room-key derivation context and invitation/recovery workflow |
| Web Crypto / @hpke/core | Cryptographic primitives and HPKE protocol | File/key layout, contexts, nonce policy, recipient wrapping and verification workflow |
| circom2 / circomlib | Circuit compiler and reusable cryptographic constraints | Credential circuit wiring and public/private input design |
| SnarkJS | Groth16 proving, verification and setup tooling | Browser/server integration, artifact management and room/session policy checks |
| poseidon-lite / @zk-kit/eddsa-poseidon | Hash and issuer signature implementations | Signed credential structure and scoped identifiers |
| qrcode | QR rendering | Invitation content and organizer-key fingerprint handling |
| Helmet / express-rate-limit / cookie | Standard security/HTTP helpers | Middleware configuration, shared limit store and session rules |
| Playwright / Supertest / Axe | Browser/API/accessibility test tools | Test scenarios, assertions and evidence |
| Vite / TypeScript / tsx | Build/typing/runtime tooling | Project configuration and application source |
| Cloudflare Tunnel / Nominatim | HTTPS tunneling / place lookup | Our sharing script and geocoding adapter |

A good presentation statement is: “We built the application protocol and workflows using established cryptographic libraries. We did not implement AES, EdDSA, HPKE or Groth16 from scratch.”

## 11. Walk through one complete feature

### Student admission

1. `ShareRoom.tsx` constructs the trusted invitation and QR.
2. `JoinPage.tsx` reads the room requirement and accepts a label and optional credential.
3. `location.ts` waits for a sufficiently precise location if the room is geographically restricted.
4. `credentialProof.ts` and `shared/credentials.ts` map the credential into circuit inputs and invoke SnarkJS with a fresh session challenge.
5. `server/rooms.ts` accepts the request; `server/zk.ts` verifies the proof, issuer and room-specific signals.
6. The room transaction checks challenge, expiry, revocation and geofence, then creates/updates membership. A unique database nullifier constraint prevents another seat with the same credential.
7. A non-credential room follows organizer approval instead of automatic proof admission.

### File publication and download

1. `RoomFiles.tsx` loads the organizer and shared room public keys and selects a file.
2. `roomCrypto.ts` generates a new file secret, encrypts metadata/chunks and wraps the secret for the organizer and shared room receiving key.
3. `uploadStore.ts` commits reservations/ciphertext locally so retries can survive reloads safely.
4. `server/roomFiles.ts` enforces owner access, quotas, immutable retries and final manifest acceptance.
5. An admitted participant receives shared envelopes. `roomCrypto.ts` uses the invitation key to open them and authenticates all content before saving plaintext.
6. `participantAccess.ts` keeps later reads subject to membership, credential, room and geographic rules.

## 12. Questions you should be ready to answer

- **Is the credential file the shared content?** No. It is the student's private eligibility credential. The organizer's shared documents use a separate encrypted file flow.
- **Can a student share their credential JSON?** Yes. It is a bearer secret. One seat per room prevents duplication inside a room, not transfer to another human. A copied credential can take the seat first. The current design does not bind it to a non-transferable device key.
- **Are these real college identities?** The bundled issuer is for demonstrations. Actual identity verification, credential delivery and institutional issuer custody must be provided by the institution.
- **Does ZKP mean all information is hidden?** No. Public eligibility attributes, expiry and scoped signals are visible; ordinary session/network metadata is also visible. Secret/signature possession is proved without uploading them through the normal join flow.
- **Is the geofence a ZKP?** No. The API evaluates reported coordinates. Coordinates can be spoofed; geofencing is a separate convenience/policy check.
- **Can the server decrypt files?** The normal storage protocol holds ciphertext and recipient envelopes, while private keys stay in browsers. A malicious server delivering altered JavaScript remains a threat.
- **Can revocation remove already downloaded files?** No. It blocks future authorized API access; it cannot erase copies.
- **Why use transactions?** To keep admission, activity logging, rotation, quotas and cleanup consistent under concurrent requests.
- **Why keep both tests and screenshots?** Tests verify behavior; screenshots/PDFs explain the interface and implementation. Neither substitutes for an independent security audit.
- **What can be demonstrated now?** Laptop/phone room sharing, manual or proof admission, encrypted transfer, key recovery/rotation, automatic access to earlier files and safe resume. Real institutional deployment still has external prerequisites documented in `DEPLOYMENT.md`.
