# Portkey

Shared setup, database schema, ordinary access controls, and room management. The frontend uses React and TypeScript; the API uses Express. PostgreSQL stores rooms, browser sessions, and membership decisions. Source code has no explanatory comments; names and small functions carry the structure.

## Run locally

Use Node.js 22.12 or newer. From this directory, run `npm ci`, then `npm run dev`. Open http://localhost:5173. The API listens on 127.0.0.1:3001. Default configuration works without an environment file. Copy `.env.example` to `.env` when changing configuration.

Local development uses PGlite, an embedded PostgreSQL engine, with persistent data under `.data/portkey`. Set `DATABASE_URL` to use a PostgreSQL server through the `pg` connection pool instead. Migrations run at startup; `npm run db:migrate` applies them separately. Migration checksums prevent silently changing an already-applied schema. Add a new numbered SQL file for future changes.

The Vite development proxy targets port 3001; set `API_ORIGIN` when using another API address. `APP_ORIGIN` must match the browser address exactly; localhost and 127.0.0.1 are different origins. For production, run `npm run build`, set `NODE_ENV=production` and an HTTPS `APP_ORIGIN`, and run `npm start` behind an HTTPS reverse proxy. The API then serves the built frontend. The included rate limiter is process-local; a multi-instance deployment needs a shared store.

## Use the module

Create a draft with a title, public description and future expiry. Edit the draft, then open it. Share the generated QR or link. In a separate browser profile, request access with a nickname or team label. The organizer approves or declines the request. An approved participant can enter the room; the organizer can remove that access or close the room.

The workspace shows room counts and lets you search titles/descriptions or filter by lifecycle status. Use an owned room as a template for another event: its title and description are prefilled, you choose a fresh deadline, and a new draft is created with a new invitation. Memberships and approvals are never copied. Closed and expired rooms can be reused without reopening the original.

The organizer's browser holds an HttpOnly session cookie. There is no registration or required name, email, roll number, or external ID. Anyone can start a session and organize a room. Session tokens are random, only their hashes are persisted, and sessions last 30 days. Rooms last at most seven days and must expire before their organizer session does. Clearing organizer cookies loses management access; recovery and co-host delegation are future modules. A participant label is self-asserted and is not verified identity. Approval must follow the organizer's own check-in process.

Room transitions are `draft → open → closed`, or `draft → closed`. Any draft/open room becomes effectively expired at its deadline. Expiry uses the database clock on requests, independent of a background worker. Closed and expired rooms cannot reopen or extend their deadlines. Owners can inspect their terminal rooms, but participants cannot enter them. Closing blocks admission; it does not delete database records.

## Organizer activity log

Each room overview includes an organizer-only timeline of creation, template reuse, metadata edits, opening, closure, access requests and admission decisions. The latest page refreshes every five seconds. Use Older activity to browse previous pages; Back to latest resumes live updates. Older pages remain stable while new actions occur. History remains readable by the owner after closure or expiry.

Migration `002_room_activity.sql` adds the history table without changing existing rooms. Activity starts when this feature is installed; earlier actions are not reconstructed. Actions and their events commit together, so a logging failure rolls back the action. Repeated join requests and unchanged edits do not add duplicate/no-op events. The API provides no history-editing endpoints. This is an operational log, not a tamper-proof audit system: a database administrator can modify stored data.

Events retain timestamps, event types, participant label snapshots and changed field names. They do not retain cookies, session tokens, IP addresses or old/new metadata values. Labels may identify participants, which is why approved participants cannot read the organizer's history. Logs share their room's current retention and are deleted with the room record. Deadline expiry is enforced by existing access checks; reaching a deadline does not create a fabricated user-action event.

## Encrypted submission inbox

An organizer can enable a private submission inbox from a room overview. The browser creates an HPKE P-256 organizer key and keeps its private half in IndexedDB. Before enabling submissions, download and store an encrypted key backup. The backup uses a passphrase and browser-side encryption; restoring it recovers the decryption key but does not restore lost room access or the browser session.

Organizer invitations include the public-key fingerprint in the URL fragment. Fragments are not sent to the server. Participants should open the invitation received directly through the organizer's trusted channel. A newly copied room link from the API does not prove the organizer's identity. Existing participants without a trusted invitation must compare the shown fingerprint with the organizer through another trusted channel before explicitly pinning it. A changed or mismatched fingerprint blocks uploads.

Files and filenames are encrypted in the participant's browser. The browser encrypts chunks one at a time with AES-256-GCM and wraps a random file key separately for the organizer and original submitter using HPKE P-256/HKDF-SHA256/AES-256-GCM. The server stores immutable ciphertext, encrypted metadata, envelopes and an acceptance receipt. It cannot list filenames or decrypt file contents. Only the room owner and original submitter can list completed submissions or retrieve their ciphertext. Current approval, room state and deadline are checked on every mutation and read. The inbox supports files up to 250 MiB, 250 chunks, 1,000 submissions per room and 5 GiB total encrypted storage; interrupted uploads are retained locally for retry and stale pending uploads are cleaned after 24 hours.

Downloads authenticate each encrypted chunk and the complete manifest before saving the plaintext. Browsers with the Origin Private File System stage verified plaintext locally before final save; browsers without that API are limited to 50 MiB fallback downloads. Browser storage can be cleared by the user or browser policy. Keep the encrypted key backup separately and protect its passphrase. Backups contain decryption keys but do not contain session authorization, room membership, pending upload ciphertext, or a way to recover an expired/removed browser session.

`GET /api/rooms/:id/activity` returns `{ events, nextCursor }`, with up to 20 newest-first events. Pass `?before=<nextCursor>` for the next page. Cursors are numeric event IDs represented as strings; all requests independently verify room ownership. Logged timestamps use the database clock.

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
| GET | `/api/join/:code` | Read public room details and own admission state |
| POST | `/api/join/:code` | Request access with `{ "label": "Team Cedar" }` |
| GET | `/api/rooms/:id/members` | List requests for the owner |
| GET | `/api/rooms/:id/activity` | Read paginated organizer-only activity |
| PATCH | `/api/rooms/:id/members/:memberId` | Decide `{ "status": "approved" }`, `denied`, or `revoked` |
| GET/POST | `/api/rooms/:id/submissions/owner-key` | Read or register the immutable organizer public key |
| GET/POST | `/api/rooms/:id/submissions/submitter-key` | Read or register the current browser's immutable submitter public key |
| POST/PUT | `/api/rooms/:id/submissions` and `/api/rooms/:id/submissions/:submissionId/metadata` | Start an encrypted upload and set its encrypted descriptor and recipient envelopes |
| PUT/POST | `/api/rooms/:id/submissions/:submissionId/chunks/:index` and `/complete` | Store immutable encrypted chunks and finalize a verified receipt |
| GET | `/api/rooms/:id/submissions` | Read a private, paginated list of completed submissions |
| GET | `/api/rooms/:id/submissions/:submissionId/chunks/:index` | Retrieve one authorized encrypted chunk |
| DELETE | `/api/rooms/:id/submissions/:submissionId` | Discard an incomplete upload |

Creation and metadata edits accept `title`, `description`, and an ISO timestamp `expiresAt` with an offset. Errors have an `error` object containing `code` and `message`. Important responses are 401 for missing/expired sessions, 403 for forbidden actions, 409 for invalid transitions, 410 for terminal rooms, and 422 for invalid input.

The duplicate endpoint requires a fresh `expiresAt`. Optional `title` and `description` override the original values; omitted values are copied. It applies the same deadline/session limits as ordinary room creation.

## Study order and verification

Read `shared/rooms.ts`, then the SQL migration, `server/sessions.ts`, `server/rooms.ts`, and the frontend components. `server/app.ts` assembles middleware and routes; `server/database.ts` separates database drivers from room logic.

Run `npm test` for API integration tests against real embedded PostgreSQL, `npm run build` for strict type checking and the frontend build, and `npm run test:e2e` for the browser workflow. Browser tests use installed Microsoft Edge on Windows; on other platforms first run `npx playwright install chromium`. They start isolated API/frontend servers on ports 3002/5174 and use `.data/e2e` rather than your development database. Desktop and mobile screenshots are saved in the parent workspace's `outputs` directory.

Anonymous membership proofs and secure device pairing are not implemented. Key verification relies on an organizer-delivered invitation or an explicit out-of-band fingerprint comparison; the app does not provide an independent identity authority.
