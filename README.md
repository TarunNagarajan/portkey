# Portkey

Shared setup, database schema, ordinary access controls, and room management. The frontend uses React and TypeScript; the API uses Express. PostgreSQL stores rooms, browser sessions, and membership decisions. Source code has no explanatory comments; names and small functions carry the structure.

## Run locally

Use Node.js 22.12 or newer. From this directory, run `npm ci`, then `npm run dev`. Open http://localhost:5173. The API listens on 127.0.0.1:3001. Default configuration works without an environment file. Copy `.env.example` to `.env` when changing configuration.

Local development uses PGlite, an embedded PostgreSQL engine, with persistent data under `.data/portkey`. Set `DATABASE_URL` to use a PostgreSQL server through the `pg` connection pool instead. Migrations run at startup; `npm run db:migrate` applies them separately. Migration checksums prevent silently changing an already-applied schema. Add a new numbered SQL file for future changes.

The Vite development proxy targets port 3001. Change `vite.config.ts` as well if changing the API port. `APP_ORIGIN` must match the browser address exactly; localhost and 127.0.0.1 are different origins. For production, run `npm run build`, set `NODE_ENV=production` and an HTTPS `APP_ORIGIN`, and run `npm start` behind an HTTPS reverse proxy. The API then serves the built frontend. The included rate limiter is process-local; a multi-instance deployment needs a shared store.

## Use the module

Create a draft with a title, public description and future expiry. Edit the draft, then open it. Share the generated QR or link. In a separate browser profile, request access with a nickname or team label. The organizer approves or declines the request. An approved participant can enter the room; the organizer can remove that access or close the room.

The organizer's browser holds an HttpOnly session cookie. There is no registration or required name, email, roll number, or external ID. Anyone can start a session and organize a room. Session tokens are random, only their hashes are persisted, and sessions last 30 days. Rooms last at most seven days and must expire before their organizer session does. Clearing organizer cookies loses management access; recovery and co-host delegation are future modules. A participant label is self-asserted and is not verified identity. Approval must follow the organizer's own check-in process.

Room transitions are `draft → open → closed`, or `draft → closed`. Any draft/open room becomes effectively expired at its deadline. Expiry uses the database clock on requests, independent of a background worker. Closed and expired rooms cannot reopen or extend their deadlines. Owners can inspect their terminal rooms, but participants cannot enter them. Closing blocks admission; it does not delete database records.

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
| GET | `/api/rooms/:id` | Read owner or approved-participant room details |
| PATCH | `/api/rooms/:id` | Replace title, description and expiry |
| POST | `/api/rooms/:id/open` | Open a draft |
| POST | `/api/rooms/:id/close` | Close a draft or open room |
| GET | `/api/join/:code` | Read public room details and own admission state |
| POST | `/api/join/:code` | Request access with `{ "label": "Team Cedar" }` |
| GET | `/api/rooms/:id/members` | List requests for the owner |
| PATCH | `/api/rooms/:id/members/:memberId` | Decide `{ "status": "approved" }`, `denied`, or `revoked` |

Creation and metadata edits accept `title`, `description`, and an ISO timestamp `expiresAt` with an offset. Errors have an `error` object containing `code` and `message`. Important responses are 401 for missing/expired sessions, 403 for forbidden actions, 409 for invalid transitions, 410 for terminal rooms, and 422 for invalid input.

## Study order and verification

Read `shared/rooms.ts`, then the SQL migration, `server/sessions.ts`, `server/rooms.ts`, and the frontend components. `server/app.ts` assembles middleware and routes; `server/database.ts` separates database drivers from room logic.

Run `npm test` for API integration tests against real embedded PostgreSQL, `npm run build` for strict type checking and the frontend build, and `npm run test:e2e` for the browser workflow. Browser tests use installed Microsoft Edge on Windows; on other platforms first run `npx playwright install chromium`. They start isolated API/frontend servers and use `.data/e2e` rather than your development database. Desktop and mobile screenshots are saved in the parent workspace's `outputs` directory.

File upload/download, anonymous membership proofs, browser file encryption, key delivery and secure device pairing are not implemented in this module. These ordinary session permissions are the foundation for those later modules, not a cryptographic privacy claim.
