# Portkey

Room management, organizer activity, and browser-encrypted private submissions. The frontend uses React and TypeScript; the API uses Express. PostgreSQL stores rooms, browser sessions, and membership decisions. Names and small functions carry the code structure.

## Run locally

Use Node.js 22.12 or newer. From this directory, run `npm ci`, then `npm run dev`. Open http://localhost:5173. The API listens on 127.0.0.1:3001. Default configuration works without an environment file. Copy `.env.example` to `.env` when changing configuration.

Local development uses PGlite, an embedded PostgreSQL engine, with persistent data under `.data/portkey`. Set `DATABASE_URL` to use a PostgreSQL server through the `pg` connection pool instead. Migrations run at startup; `npm run db:migrate` applies them separately. Migration checksums prevent silently changing an already-applied schema. Add a new numbered SQL file for future changes.

The Vite development proxy targets port 3001; set `API_ORIGIN` when using another API address. `APP_ORIGIN` must match the browser address exactly; localhost and 127.0.0.1 are different origins. Local development binds the API to 127.0.0.1:3001 and the Vite page to 127.0.0.1:5173. Phone testing uses separate port 3003 and `.data/phone-demo`. Place search for room areas uses OpenStreetMap Nominatim and needs outbound network access; set `GEOCODING=false` to disable it. For production, set `NODE_ENV=production`, provide `DATABASE_URL`, and set the canonical HTTPS `APP_ORIGIN` (or use Render's `RENDER_EXTERNAL_URL` fallback). Set `HOST=0.0.0.0` when a platform must reach the service and configure only the known proxy hop count with `TRUST_PROXY_HOPS`. The API serves the built frontend. Production refuses an embedded database unless `ALLOW_EMBEDDED_DATABASE=true` is explicitly set for a disposable demo. The included rate limiter is process-local; a multi-instance deployment needs a shared store.

## Free public hosting with Render and Neon

The included `render.yaml` creates one free Node web service from this repository's `main` branch. To deploy it, push the repository to a public GitHub repository, create a free Neon project, and copy its pooled PostgreSQL connection string with SSL enabled. In Render, choose **New → Blueprint**, connect the public repository, and apply the Blueprint. When prompted, set `DATABASE_URL` to the Neon pooled connection string as a secret. Never put the value in Git, an issue, or a chat. Render supplies the service's public HTTPS address; the app uses it as the invitation origin unless you explicitly set `APP_ORIGIN`.

After deployment, open the Render HTTPS URL and create a room. Scan its QR code with a phone on a separate network, confirm the browser shows the same public host, and submit a join request. A free Render service can take a short while to wake after inactivity; the free web service sleeps after 15 minutes without inbound traffic. Neon currently lists 1 GB storage and 100 compute-unit hours per month for its free plan, with no credit card required. These are provider limits that can change. Portkey's 5 GiB per-room submission limit is an application ceiling, not storage promised by the free database plan; leave substantial room for indexes and room data. See [Render free services](https://render.com/docs/free), [Render Blueprint configuration](https://render.com/docs/blueprint-spec), and [Neon pricing](https://neon.tech/pricing) for current limits.

If the Render hostname changes, the invitation origin changes too. Create new invitations from the new address. Existing browser cookies and locally stored organizer keys belong to that browser and origin; retain the encrypted key backup and its passphrase separately. A hostname change does not transfer browser sessions, keys, or local backup data.

## Temporary phone demo

Install the official `cloudflared` executable separately, then run `npm run phone:demo`. The command rebuilds the current app and launches a temporary HTTPS tunnel to it on 127.0.0.1:3003. It uses the executable on `PATH` or the path in `CLOUDFLARED_PATH`, and stores demo data under `.data/phone-demo`. Set `PORTKEY_DEMO_PORT` to choose a different available port. The launcher does not read `.env` or inherit `DATABASE_URL`; it uses an isolated local database. Keep the computer and terminal running during the demo. A new `trycloudflare.com` address can take a couple of minutes to resolve publicly; startup checks its public HTTPS health for up to three minutes and reports an actionable error if it remains unreachable. The address is temporary and is not permanent hosting. Installation instructions are in [Cloudflare's official downloads guide](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).

## Use the module

Create a draft with a title, public description and future expiry. Edit the draft, then open it. Share the generated QR or link. In a separate browser profile, request access with a nickname or team label. The organizer approves or declines the request. An approved participant can enter the room; the organizer can remove that access or close the room.

The workspace shows room counts and lets you search titles/descriptions or filter by lifecycle status. Use an owned room as a template for another event: its title and description are prefilled, you choose a fresh deadline, and a new draft is created with a new invitation. Memberships and approvals are never copied. Closed and expired rooms can be reused without reopening the original.

The organizer's browser holds an HttpOnly session cookie. There is no registration or required name, email, roll number, or external ID. Anyone can start a session and organize a room. Session tokens are random, only their hashes are persisted, and sessions last 30 days. Rooms last at most seven days and must expire before their organizer session does. Clearing organizer cookies loses management access; recovery and co-host delegation are future modules. A participant label is self-asserted and is not verified identity. Approval must follow the organizer's own check-in process.

Room transitions are `draft → open → closed`, or `draft → closed`. Any draft/open room becomes effectively expired at its deadline. Expiry uses the database clock on requests, independent of a background worker. Closed and expired rooms cannot reopen or extend their deadlines. Owners can inspect their terminal rooms, but participants cannot enter them. Closing blocks admission; room expiry separately triggers submission cleanup for rooms whose cleanup policy is enabled.

New rooms automatically remove their encrypted submission records after the room deadline. A server cleanup pass runs at startup and about every 60 seconds while running; removal usually happens within a minute, subject to a bounded backlog, and passes resume after downtime. Closing a room early does not trigger deletion; an allowed deadline edit while active changes the cleanup deadline. Historical rooms keep cleanup disabled until the owner explicitly enables it. Incomplete uploads are removed after 24 hours regardless of room policy. This is logical deletion from the active database: room history, membership, public keys and room metadata remain, while backups, browser keys and already downloaded copies follow their own retention.

## Organizer activity log

Each room overview includes an organizer-only timeline of creation, template reuse, metadata edits, opening, closure, access requests and admission decisions. The latest page refreshes every five seconds. Use Older activity to browse previous pages; Back to latest resumes live updates. Older pages remain stable while new actions occur. History remains readable by the owner after closure or expiry.

Migration `002_room_activity.sql` adds the history table without changing existing rooms. Activity starts when this feature is installed; earlier actions are not reconstructed. Actions and their events commit together, so a logging failure rolls back the action. Repeated join requests and unchanged edits do not add duplicate/no-op events. The API provides no history-editing endpoints. This is an operational log, not a tamper-proof audit system: a database administrator can modify stored data.

Events retain timestamps, event types, participant label snapshots and changed field names. They do not retain cookies, session tokens, IP addresses or old/new metadata values. Labels may identify participants, which is why approved participants cannot read the organizer's history. Logs share their room's current retention and are deleted with the room record. Deadline expiry is enforced by existing access checks; reaching a deadline does not create a fabricated user-action event.

## Encrypted submission inbox

An organizer can enable a private submission inbox from a room overview. The browser creates an HPKE P-256 organizer key and keeps its private half in IndexedDB. Before inviting submissions, download and store an encrypted key backup. The backup uses a passphrase and browser-side encryption; restoring it recovers the decryption key but does not restore lost room access or the browser session.

Organizer invitations include the public-key fingerprint in the URL fragment. Browsers omit URL fragments from HTTP requests; Portkey does not transmit the invitation fingerprint fragment. Organizer links use a fingerprint verified against the locally held organizer key. Participants should open the invitation received directly through the organizer's trusted channel. A newly copied room link from the API does not prove the organizer's identity. Existing participants without a trusted invitation must compare the shown fingerprint with the organizer through another trusted channel before explicitly pinning it. A changed or mismatched fingerprint blocks uploads.

Files and filenames are encrypted in the participant's browser. The browser encrypts chunks one at a time with AES-256-GCM and wraps a random file key separately for the organizer and original submitter using HPKE P-256/HKDF-SHA256/AES-256-GCM. The server stores immutable ciphertext, encrypted metadata, envelopes and an acceptance receipt. It cannot list filenames or decrypt file contents. Only the room owner and original submitter can list completed submissions or retrieve their ciphertext. Current approval, room state and deadline are checked on every mutation and read. The inbox supports files up to 250 MiB, 250 chunks, 1,000 submissions per room and 5 GiB total encrypted storage; interrupted uploads are retained locally for retry and starting a fresh upload removes pending uploads older than 24 hours. Limits allocate encrypted chunk bytes under the room lock; capacity for an entire file is not reserved in advance. Metadata and envelope storage is separately bounded by payload and object limits.

Downloads authenticate each encrypted chunk and the complete manifest before saving the plaintext. Browsers with the Origin Private File System stage plaintext locally and verify it before final save. A save-file picker copies verified data to the chosen file and removes staging. Standard browser downloads retain their temporary source until you use Remove local download copies after saving; at most five copies are accepted sequentially. This avoids canceling an active download. Browsers without private file storage are limited to 50 MiB memory downloads. Browser storage can be cleared by the user or browser policy. Keep the encrypted key backup separately and protect its passphrase. Backups contain decryption keys but do not contain session authorization, room membership, pending upload ciphertext, or a way to recover an expired/removed browser session.

`GET /api/rooms/:id/activity` returns `{ events, nextCursor }`, with up to 20 newest-first events. Pass `?before=<nextCursor>` for the next page. Cursors are numeric event IDs represented as strings; all requests independently verify room ownership. Logged timestamps use the database clock.

### Encryption and trust limits

Every upload has a fresh 32-byte secret and 32-byte HKDF salt. Separate HKDF-SHA256 labels derive content and metadata AES-256-GCM keys. Chunk nonces combine a random eight-byte prefix with a four-byte big-endian index; metadata uses a separate random 12-byte nonce and key. IndexedDB reserves each index before encryption and atomically saves its immutable ciphertext. If that ciphertext is lost after reservation, the upload must be discarded and restarted with a fresh key. A retry never encrypts changed data with the old nonce.

HPKE uses RFC 9180 Base mode with P-256/HKDF-SHA256/AES-256-GCM. Envelope info and authenticated data bind protocol version, room, upload, recipient fingerprint and purpose. Metadata binds room/upload/purpose; chunk authenticated data additionally binds index and plaintext length. Completion verifies a SHA-256 manifest of the encrypted descriptor and ordered ciphertext hashes. A receipt records server acceptance and is not an independent signed attestation. The library is checked against the [published RFC test-vector revision](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json).

Key backups use PBKDF2-HMAC-SHA256 with 600,000 iterations, a random 16-byte salt and AES-256-GCM with a random 12-byte nonce. Version 1 fixes the KDF cost rather than accepting attacker-supplied iteration counts. Inputs and decoded byte lengths are bounded before derivation. Restoration checks the room, public fingerprint and private/public key match before retaining a key. Passphrases stay in the browser.

Content encryption assumes the intended browser application executes. A malicious server serving modified JavaScript could steal plaintext or keys. Session relationships, admission labels, room descriptions, sizes, timings and network addresses are not concealed by this feature. Private keys, pending upload keys and decrypted download copies are local browser data; they are not protected against compromise of that browser or device. Closure and expiry block future API access. Submission cleanup logically deletes encrypted submission rows from the active database, but does not erase backups, browser keys or files already saved by a recipient.

## Location-restricted rooms

An organizer can restrict a draft room to a circular area so that only devices physically inside it can request access or enter. Set the area from a room overview: search for a place (for example a city or campus) or use your current location, then adjust the radius from 50 metres to 50 kilometres. Place search uses OpenStreetMap Nominatim and only supplies a centre, a suggested radius and a display label. Disable it with `GEOCODING=false`, or point `NOMINATIM_URL` at another geocoder.

A participant must send a fresh, accurate location fix with a join request. The server computes the great-circle distance and rejects requests outside the area with `403 GEO_OUTSIDE`, missing or denied location with `403 GEO_REQUIRED`, a stale reading with `403 GEO_STALE`, and a low-accuracy reading with `422 GEO_INACCURATE`. Approved participants re-share a fix on entry: the last reading must be inside the area and no more than five minutes old, otherwise entry is refused with `403 GEO_STALE` or `403 GEO_OUTSIDE`. Without a location, a participant cannot join or enter. The area is fixed once the room opens and can be cleared while it is still a draft.

Coordinates and accuracy are stored on the membership so the organizer can see whether a participant was inside and how far away they were. The browser requests a location only when joining, entering, or refreshing an expired reading. This is presence at the moment of the request, not proof of residence. Because the server must evaluate the distance, the participant's approximate coordinates reach the server; unlike submission contents, they are not end-to-end encrypted.

## Database and access boundaries

`sessions` contains hashed browser credentials and their expiry. `rooms` belongs to one organizer session and has a unique random join address. `memberships` links one browser session to one room with a pending, approved, denied, or revoked status. `schema_migrations` records applied SQL and checksums. Foreign keys, uniqueness, checks and indexes are defined in `server/migrations/001_initial.sql`.

The public join page exposes only title, description, effective status and deadline, plus the caller's own membership state. Private room entry requires approved membership. Only the room owner can edit metadata, change lifecycle, inspect requests or decide membership. Approval and lifecycle changes lock the room in a transaction so concurrent requests cannot bypass closure. Revoked and denied sessions cannot request access again to that room. A new browser session can request again, so this prototype does not implement a human-level ban.

Writes require the configured Origin and a CSRF token derived from the session secret. Cookies are HttpOnly and SameSite=Strict, and gain Secure plus the `__Host-` prefix in production. API responses use no-store caching, JSON payloads have a size limit, input objects reject unknown fields, SQL uses parameters, and request limits use browser sessions rather than grouping every workshop participant under one Wi-Fi address.

## API

Start with `POST /api/session` and an `Origin` header equal to `APP_ORIGIN`. Preserve its cookie and use the returned `csrfToken` as `X-CSRF-Token` on subsequent writes. All remaining room routes require a valid session.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Database readiness |
| POST | `/api/session` | Start or reuse a browser session |
| GET | `/api/rooms` | List the caller's owned/requested rooms |
| POST | `/api/rooms` | Create a draft |
| POST | `/api/rooms/:id/duplicate` | Create an owner-only draft from a room template |
| GET | `/api/rooms/:id` | Read owner or approved-participant room details |
| PATCH | `/api/rooms/:id` | Replace title, description and expiry |
| POST | `/api/rooms/:id/open` | Open a draft |
| POST | `/api/rooms/:id/close` | Close a draft or open room |
| POST | `/api/rooms/:id/submission-cleanup` | Owner enables irreversible automatic cleanup with an empty JSON object |
| GET | `/api/join/:code` | Read public room details and own admission state |
| POST | `/api/join/:code` | Request access with `{ "label": "Team Cedar" }` and, for a restricted room, `{ lat, lng, accuracyM, timestamp }` |
| GET | `/api/geo/search` | Search places for a room area with `?q=Warangal` |
| POST | `/api/rooms/:id/geo` | Owner sets a draft room's area with `{ lat, lng, radiusM, label?, source? }` |
| DELETE | `/api/rooms/:id/geo` | Owner clears a draft room's area |
| GET | `/api/rooms/:id/members` | List requests for the owner |
| GET | `/api/rooms/:id/activity` | Read paginated organizer-only activity |
| PATCH | `/api/rooms/:id/members/:memberId` | Decide `{ "status": "approved" }`, `denied`, or `revoked` |
| GET | `/api/rooms/:id/submissions/keys` | Read public recipient keys for the owner or approved participant |
| POST | `/api/rooms/:id/submissions/owner-key` | Register the immutable organizer public key |
| POST | `/api/rooms/:id/submissions/submitter-key` | Register the current browser's immutable submitter public key |
| POST/PUT | `/api/rooms/:id/submissions` and `/api/rooms/:id/submissions/:submissionId/metadata` | Start an encrypted upload and set its encrypted descriptor and recipient envelopes |
| PUT/POST | `/api/rooms/:id/submissions/:submissionId/chunks/:index` and `/complete` | Store immutable encrypted chunks and finalize a verified receipt |
| GET | `/api/rooms/:id/submissions` | Read a private, paginated list of completed submissions |
| GET | `/api/rooms/:id/submissions/:submissionId/chunks/:index` | Retrieve one authorized encrypted chunk |
| DELETE | `/api/rooms/:id/submissions/:submissionId` | Discard an incomplete upload |

Creation and metadata edits accept `title`, `description`, and an ISO timestamp `expiresAt` with an offset. Errors have an `error` object containing `code` and `message`. Important responses are 401 for missing/expired sessions, 403 for forbidden actions, 409 for invalid transitions, 410 for terminal rooms, and 422 for invalid input.

The duplicate endpoint requires a fresh `expiresAt`. Optional `title` and `description` override the original values; omitted values are copied. It applies the same deadline/session limits as ordinary room creation.

## Study order and verification

Read `shared/rooms.ts`, then the SQL migration, `server/sessions.ts`, `server/rooms.ts`, and the frontend components. `server/app.ts` assembles middleware and routes; `server/database.ts` separates database drivers from room logic.

Run `npm test` for API integration tests against real embedded PostgreSQL, `npm run build` for strict type checking and the frontend build, and `npm run test:e2e` for the browser workflow. Browser tests use installed Microsoft Edge on Windows; on other platforms first run `npx playwright install chromium`. They start isolated API/frontend servers on ports 3002/5174 and use `.data/e2e-private-inbox` rather than your development database. Desktop and mobile screenshots are saved in the parent workspace's `outputs` directory.

Anonymous membership proofs and secure device pairing are not implemented. Key verification relies on an organizer-delivered invitation or an explicit out-of-band fingerprint comparison; the app does not provide an independent identity authority.
