import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import supertest from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import type { Room } from '../shared/rooms.js';

const origin = 'http://localhost:5173';
let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
});
after(async () => database.close());

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = response.body.csrfToken as string;
  const cookies = response.headers['set-cookie'];
  const cookie = Array.isArray(cookies) ? cookies[0] : cookies;
  const sessionToken = cookie.split(';')[0].split('=')[1];
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions WHERE token_hash = $1',
    [createHash('sha256').update(sessionToken).digest('hex')],
  );
  return {
    agent,
    csrf,
    sessionId: session.id,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) => agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
  };
}
type Browser = Awaited<ReturnType<typeof browser>>;
const roomInput = (admissionPolicy?: 'approval' | 'pass') => ({
  title: 'Workshop', description: 'Materials', expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  ...(admissionPolicy ? { admissionPolicy } : {}),
});
async function createRoom(owner: Browser, policy?: 'approval' | 'pass') {
  return (await owner.post('/rooms', roomInput(policy)).expect(201)).body as Room;
}
async function openRoom(owner: Browser, room: Room) {
  return (await owner.post(`/rooms/${room.id}/open`).expect(200)).body as Room;
}

test('migration 007 upgrades existing rooms and activity without changing old migrations', async () => {
  const legacy = await openDatabase();
  try {
    await legacy.exec(`CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`);
    const migrationDirectory = fileURLToPath(new URL('../server/migrations/', import.meta.url));
    for (const name of ['001_initial.sql', '002_room_activity.sql', '003_private_submissions.sql', '004_submission_limits.sql', '005_submission_retention.sql', '006_geofence.sql']) {
      const sql = (await readFile(join(migrationDirectory, name), 'utf8')).replace(/\r\n/g, '\n');
      await legacy.exec(sql);
      await legacy.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [name, createHash('sha256').update(sql).digest('hex')]);
    }
    const ownerId = randomUUID();
    const roomId = randomUUID();
    await legacy.query('INSERT INTO sessions (id, token_hash, expires_at) VALUES ($1, $2, clock_timestamp() + interval \'1 day\')', [ownerId, randomBytes(32).toString('hex')]);
    await legacy.query('INSERT INTO rooms (id, owner_id, join_code, title, expires_at) VALUES ($1, $2, $3, $4, clock_timestamp() + interval \'1 hour\')', [roomId, ownerId, randomBytes(12).toString('base64url'), 'Legacy room']);
    await legacy.query("INSERT INTO room_activity (room_id, kind) VALUES ($1, 'room_created')", [roomId]);
    await migrate(legacy);
    const [room] = await legacy.query<{ admission_policy: string }>('SELECT admission_policy FROM rooms WHERE id = $1', [roomId]);
    assert.equal(room.admission_policy, 'approval');
    const [activity] = await legacy.query<{ kind: string }>('SELECT kind FROM room_activity WHERE room_id = $1', [roomId]);
    assert.equal(activity.kind, 'room_created');
    await legacy.query("INSERT INTO room_activity (room_id, kind, changed_fields) VALUES ($1, 'room_updated', ARRAY['admissionPolicy'])", [roomId]);
    await assert.rejects(() => legacy.query("INSERT INTO room_activity (room_id, kind, changed_fields) VALUES ($1, 'room_updated', ARRAY['unknown'])", [roomId]));
  } finally { await legacy.close(); }
});

test('pass rooms issue digest-only one-use tokens and redeem atomically for the matching browser', async (context) => {
  context.mock.method(console, 'error', () => {});
  const owner = await browser();
  const attendee = await browser();
  const other = await browser();
  const room = await createRoom(owner, 'pass');
  const oldRoom = await createRoom(owner);
  assert.equal(oldRoom.admissionPolicy, 'approval');
  await owner.patch(`/rooms/${room.id}`, { title: room.title, description: room.description, expiresAt: room.expiresAt }).expect(200);
  const template = (await owner.post(`/rooms/${room.id}/duplicate`, { expiresAt: roomInput().expiresAt }).expect(201)).body as Room;
  assert.equal(template.admissionPolicy, 'pass');
  assert.deepEqual(await owner.get(`/rooms/${template.id}/passes`).expect(200).then((response) => response.body), []);
  await openRoom(owner, room);

  await attendee.post(`/join/${room.joinCode}`, { label: 'No pass' }).expect(409).expect(({ body }) => assert.equal(body.error.code, 'PASS_REQUIRED'));
  await owner.post(`/rooms/${room.id}/passes`, { count: 1, unexpected: true }).expect(422);
  await owner.agent.post(`/api/rooms/${room.id}/passes`).send({ count: 1 }).expect(403);
  await owner.agent.post(`/api/rooms/${room.id}/passes`)
    .set('Origin', 'https://attacker.example')
    .set('X-CSRF-Token', owner.csrf)
    .send({ count: 1 })
    .expect(403);
  await other.get(`/rooms/${room.id}/passes`).expect(403);
  await database.exec("ALTER TABLE room_activity ADD CONSTRAINT test_issue_failure CHECK (kind <> 'admission_passes_issued') NOT VALID");
  try {
    await owner.post(`/rooms/${room.id}/passes`, { count: 1 }).expect(500);
    const [count] = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM room_admission_passes WHERE room_id = $1', [room.id]);
    assert.equal(count.count, 0);
  } finally { await database.exec('ALTER TABLE room_activity DROP CONSTRAINT test_issue_failure'); }
  const issued = await owner.post(`/rooms/${room.id}/passes`, { count: 3 }).expect(201);
  const passes = issued.body.passes as Array<{ id: string; number: number; token: string }>;
  assert.equal(passes.length, 3);
  assert.equal(new Set(passes.map((pass) => pass.token)).size, 3);
  assert.ok(passes.every((pass) => /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(pass.token)));
  const stored = await database.query<{ token_digest: Buffer }>('SELECT token_digest FROM room_admission_passes WHERE room_id = $1 ORDER BY pass_number', [room.id]);
  assert.deepEqual(
    stored.map((row) => Buffer.from(row.token_digest).toString('hex')),
    passes.map((pass) => createHash('sha256').update(Buffer.from(pass.token, 'base64url')).digest('hex')),
  );
  const listed = await owner.get(`/rooms/${room.id}/passes`).expect(200);
  assert.equal(JSON.stringify(listed.body).includes(passes[0].token), false);
  assert.equal(JSON.stringify(listed.body).includes('token_digest'), false);
  await owner.post(`/rooms/${room.id}/passes`, { count: 21 }).expect(422);

  const token = passes[0].token;
  await database.exec("ALTER TABLE room_activity ADD CONSTRAINT test_redemption_failure CHECK (kind <> 'pass_redeemed') NOT VALID");
  try {
    await attendee.post(`/join/${room.joinCode}/redeem`, { token, label: 'Team Cedar' }).expect(500);
    const [count] = await database.query<{ count: number }>("SELECT count(*)::int AS count FROM memberships WHERE room_id = $1 AND status = 'approved'", [room.id]);
    assert.equal(count.count, 0);
    const [unused] = await database.query<{ redeemed_at: Date | null }>('SELECT redeemed_at FROM room_admission_passes WHERE id = $1', [passes[0].id]);
    assert.equal(unused.redeemed_at, null);
  } finally { await database.exec('ALTER TABLE room_activity DROP CONSTRAINT test_redemption_failure'); }
  await attendee.post(`/join/${room.joinCode}/redeem`, { token, label: 'Team Cedar' }).expect(200).expect(({ body }) => assert.equal(body.status, 'approved'));
  await attendee.post(`/join/${room.joinCode}/redeem`, { token, label: 'Ignored rename' }).expect(200);
  await other.post(`/join/${room.joinCode}/redeem`, { token, label: 'Team Pine' }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_PASS_INVALID'));
  const [redeemed] = await database.query<{ redeemer_session_id: string | null; redeemed_at: Date | null }>(
    'SELECT redeemer_session_id, redeemed_at FROM room_admission_passes WHERE id = $1', [passes[0].id],
  );
  assert.ok(redeemed.redeemer_session_id);
  assert.ok(redeemed.redeemed_at);
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: passes[1].token, label: 'Already in' })
    .expect(409).expect(({ body }) => assert.equal(body.error.code, 'ALREADY_ADMITTED'));
  const [unusedSecond] = await database.query<{ redeemed_at: Date | null }>(
    'SELECT redeemed_at FROM room_admission_passes WHERE id = $1', [passes[1].id],
  );
  assert.equal(unusedSecond.redeemed_at, null);
  await attendee.get(`/rooms/${room.id}`).expect(200);
  await attendee.get(`/rooms/${room.id}/submissions`).expect(200);
  await other.get(`/rooms/${room.id}/submissions`).expect(403);
  const [member] = await database.query<{ id: string }>(
    'SELECT id FROM memberships WHERE room_id = $1 AND session_id = $2',
    [room.id, attendee.sessionId],
  );
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'revoked' }).expect(200);
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: passes[1].token, label: 'Removed' })
    .expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_DENIED'));
  const denied = await browser();
  await database.query(
    "INSERT INTO memberships (id, room_id, session_id, label, status, decided_at) VALUES ($1, $2, $3, 'Declined browser', 'denied', clock_timestamp())",
    [randomUUID(), room.id, denied.sessionId],
  );
  await denied.post(`/join/${room.joinCode}/redeem`, { token: passes[2].token, label: 'Denied' })
    .expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_DENIED'));
  await owner.patch(`/rooms/${room.id}/passes/${passes[0].id}`, { status: 'revoked' }).expect(409);
  const [events] = await database.query<{ count: number }>("SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind = 'pass_redeemed'", [room.id]);
  assert.equal(events.count, 1);
});

test('revocation is idempotent and location failures never consume passes', async () => {
  const owner = await browser();
  const attendee = await browser();
  const competitor = await browser();
  const room = await createRoom(owner, 'pass');
  await owner.post(`/rooms/${room.id}/geo`, { lat: 17.385, lng: 78.487, radiusM: 500, label: 'Workshop' }).expect(200);
  await openRoom(owner, room);
  const issued = await owner.post(`/rooms/${room.id}/passes`, { count: 2 }).expect(201);
  const [revokable, geofenced] = issued.body.passes as Array<{ id: string; token: string }>;
  await owner.patch(`/rooms/${room.id}/passes/${revokable.id}`, { status: 'revoked' }).expect(200);
  await owner.patch(`/rooms/${room.id}/passes/${revokable.id}`, { status: 'revoked' }).expect(200);
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: revokable.token, label: 'Revoked' }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_PASS_INVALID'));
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: geofenced.token, label: 'Outside', lat: 0, lng: 0, accuracyM: 10, timestamp: new Date().toISOString() }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'GEO_OUTSIDE'));
  const [row] = await database.query<{ redeemed_at: Date | null; revoked_at: Date | null }>('SELECT redeemed_at, revoked_at FROM room_admission_passes WHERE id = $1', [geofenced.id]);
  assert.equal(row.redeemed_at, null);
  assert.equal(row.revoked_at, null);
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: geofenced.token, label: 'Needs location' }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'GEO_REQUIRED'));
  const fix = { lat: 17.385, lng: 78.487, accuracyM: 10, timestamp: new Date().toISOString() };
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: geofenced.token, label: 'Inside', ...fix }).expect(200);
  await competitor.post(`/join/${room.joinCode}/redeem`, { token: geofenced.token, label: 'Used elsewhere' }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_PASS_INVALID'));
  await attendee.post(`/join/${room.joinCode}/redeem`, { token: geofenced.token, label: 'Retry' }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'GEO_REQUIRED'));
  const [activity] = await database.query<{ revoked: number }>("SELECT count(*) FILTER (WHERE kind = 'pass_revoked')::int AS revoked FROM room_activity WHERE room_id = $1", [room.id]);
  assert.equal(activity.revoked, 1);
});

test('policy changes only in drafts and draft, closed, expired, and cross-room claims are rejected', async () => {
  const owner = await browser();
  const attendee = await browser();
  const standard = await createRoom(owner);
  const changed = await owner.patch(`/rooms/${standard.id}`, {
    ...roomInput('pass'),
    expiresAt: standard.expiresAt,
  }).expect(200);
  assert.equal(changed.body.admissionPolicy, 'pass');
  const event = await owner.get(`/rooms/${standard.id}/activity`).expect(200);
  assert.deepEqual(event.body.events[0].changedFields, ['admissionPolicy']);

  const unchanged = await owner.patch(`/rooms/${standard.id}`, {
    title: standard.title,
    description: standard.description,
    expiresAt: standard.expiresAt,
  }).expect(200);
  assert.equal(unchanged.body.admissionPolicy, 'pass');
  await openRoom(owner, changed.body as Room);
  await owner.patch(`/rooms/${standard.id}`, roomInput('approval'))
    .expect(409).expect(({ body }) => assert.equal(body.error.code, 'POLICY_LOCKED'));
  const issued = await owner.post(`/rooms/${standard.id}/passes`, { count: 1 }).expect(201);
  const token = issued.body.passes[0].token as string;

  const otherRoom = await createRoom(owner, 'pass');
  await openRoom(owner, otherRoom);
  await attendee.post(`/join/${otherRoom.joinCode}/redeem`, { token, label: 'Wrong room' })
    .expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_PASS_INVALID'));

  const draft = await createRoom(owner, 'pass');
  const draftPass = await owner.post(`/rooms/${draft.id}/passes`, { count: 1 }).expect(201);
  await attendee.post(`/join/${draft.joinCode}/redeem`, {
    token: draftPass.body.passes[0].token, label: 'Too early',
  }).expect(409).expect(({ body }) => assert.equal(body.error.code, 'ROOM_NOT_OPEN'));
  await openRoom(owner, draft);
  await owner.post(`/rooms/${draft.id}/close`).expect(200);
  await attendee.post(`/join/${draft.joinCode}/redeem`, {
    token: draftPass.body.passes[0].token, label: 'Closed room',
  }).expect(410);

  const expired = await createRoom(owner, 'pass');
  const expiredPass = await owner.post(`/rooms/${expired.id}/passes`, { count: 1 }).expect(201);
  await database.query(`
    UPDATE rooms
    SET created_at = clock_timestamp() - interval '2 hours',
        expires_at = clock_timestamp() - interval '1 minute'
    WHERE id = $1
  `, [expired.id]);
  await attendee.post(`/join/${expired.joinCode}/redeem`, {
    token: expiredPass.body.passes[0].token, label: 'Expired room',
  }).expect(410);
  const terminalList = await owner.get(`/rooms/${expired.id}/passes`).expect(200);
  assert.equal(terminalList.body[0].status, 'expired');
});

test('room locking allows one competing claim and orders revocation and closure against redemption', async () => {
  const owner = await browser();
  const first = await browser();
  const second = await browser();
  const third = await browser();
  const room = await createRoom(owner, 'pass');
  await openRoom(owner, room);
  const issued = await owner.post(`/rooms/${room.id}/passes`, { count: 4 }).expect(201);
  const tokens = issued.body.passes as Array<{ id: string; token: string }>;

  const competing = await Promise.all([
    first.post(`/join/${room.joinCode}/redeem`, { token: tokens[0].token, label: 'First' }),
    second.post(`/join/${room.joinCode}/redeem`, { token: tokens[0].token, label: 'Second' }),
  ]);
  assert.deepEqual(competing.map((response) => response.status).sort(), [200, 403]);
  const [claims] = await database.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind = 'pass_redeemed'",
    [room.id],
  );
  assert.equal(claims.count, 1);

  const [revoke, redeem] = await Promise.all([
    owner.patch(`/rooms/${room.id}/passes/${tokens[1].id}`, { status: 'revoked' }),
    third.post(`/join/${room.joinCode}/redeem`, { token: tokens[1].token, label: 'Racing claim' }),
  ]);
  assert.ok((revoke.status === 200 && redeem.status === 403) || (revoke.status === 409 && redeem.status === 200));

  const fourth = await browser();
  const [close, finalClaim] = await Promise.all([
    owner.post(`/rooms/${room.id}/close`),
    fourth.post(`/join/${room.joinCode}/redeem`, { token: tokens[2].token, label: 'Closing claim' }),
  ]);
  assert.equal(close.status, 200);
  assert.ok(finalClaim.status === 200 || finalClaim.status === 410);
  await owner.get(`/rooms/${room.id}/passes`).expect(200);
  const afterClose = await browser();
  await afterClose.post(`/join/${room.joinCode}/redeem`, {
    token: tokens[3].token, label: 'After close',
  }).expect(410);
});

test('the lifetime cap includes all passes and redeemed tokens stay consumed after session deletion', async () => {
  const owner = await browser();
  const attendee = await browser();
  const room = await createRoom(owner, 'pass');
  await openRoom(owner, room);
  const pass = await owner.post(`/rooms/${room.id}/passes`, { count: 1 }).expect(201);
  await attendee.post(`/join/${room.joinCode}/redeem`, {
    token: pass.body.passes[0].token, label: 'Persistent consumption',
  }).expect(200);
  await database.query('DELETE FROM memberships WHERE room_id = $1 AND session_id = $2', [room.id, attendee.sessionId]);
  await database.query('DELETE FROM sessions WHERE id = $1', [attendee.sessionId]);
  const replacement = await browser();
  await replacement.post(`/join/${room.joinCode}/redeem`, {
    token: pass.body.passes[0].token, label: 'New browser',
  }).expect(403).expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_PASS_INVALID'));
  const [used] = await database.query<{ redeemed_at: Date | null; redeemer_session_id: string | null }>(
    'SELECT redeemed_at, redeemer_session_id FROM room_admission_passes WHERE id = $1', [pass.body.passes[0].id],
  );
  assert.ok(used.redeemed_at);
  assert.equal(used.redeemer_session_id, null);

  const capped = await createRoom(owner, 'pass');
  await database.query(
    `INSERT INTO room_admission_passes (id, room_id, pass_number, token_digest)
     SELECT ('00000000-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid,
       $1, n, decode(md5(n::text) || md5((n + 1000)::text), 'hex')
     FROM generate_series(1, 1000) AS n`,
    [capped.id],
  );
  await openRoom(owner, capped);
  const passList = await owner.get(`/rooms/${capped.id}/passes`).expect(200);
  await owner.patch(`/rooms/${capped.id}/passes/${passList.body[0].id}`, { status: 'revoked' }).expect(200);
  await owner.post(`/rooms/${capped.id}/passes`, { count: 1 })
    .expect(409).expect(({ body }) => assert.equal(body.error.code, 'PASS_LIMIT'));
  assert.equal((await owner.get(`/rooms/${capped.id}/passes`).expect(200)).body.length, 1000);
});
