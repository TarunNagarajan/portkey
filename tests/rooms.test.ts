import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import supertest from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import type { Room } from '../shared/rooms.js';
import type { ActivityPage } from '../shared/activity.js';
import { recordActivity, readActivity } from '../server/activity.js';

const origin = 'http://localhost:5173';
let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
});
after(async () => {
  await database.close();
});

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = response.body.csrfToken as string;
  const cookie = (response.headers['set-cookie'] as unknown as string[])[0];
  const token = cookie.split(';')[0].split('=')[1];
  return {
    agent,
    csrf,
    token,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) =>
      agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) =>
      agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
  };
}

type Browser = Awaited<ReturnType<typeof browser>>;
const input = () => ({
  title: 'Workshop',
  description: 'Materials and submissions',
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
});

async function createRoom(owner: Browser, open = false): Promise<Room> {
  const response = await owner.post('/rooms', input()).expect(201);
  const room = response.body as Room;
  if (open) return (await owner.post(`/rooms/${room.id}/open`).expect(200)).body as Room;
  return room;
}

async function requestAdmission(participant: Browser, room: Room) {
  return (await participant.post(`/join/${room.joinCode}`, { label: 'Team Cedar' }).expect(200))
    .body as { id: string; status: string };
}

test('health checks the database and API requires a session', async () => {
  await supertest(app).get('/api/health').expect(200);
  await supertest(app).get('/api/rooms').expect(401);
});

test('sessions use HttpOnly cookies and only token hashes are stored', async () => {
  const client = await browser();
  const response = await client.agent.post('/api/session').set('Origin', origin).expect(200);
  assert.equal(response.body.csrfToken, client.csrf);
  const [stored] = await database.query<{ token_hash: string }>(
    'SELECT token_hash FROM sessions WHERE token_hash = $1',
    [createHash('sha256').update(client.token).digest('hex')],
  );
  assert.notEqual(stored.token_hash, client.token);
  const fresh = await supertest(app).post('/api/session').set('Origin', origin).expect(200);
  const cookie = (fresh.headers['set-cookie'] as unknown as string[])[0];
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
});

test('production cookies have the secure host prefix', async () => {
  const secure = createApp(database, {
    origin: 'https://portkey.example',
    secure: true,
    rateLimiting: false,
  });
  const response = await supertest(secure)
    .post('/api/session')
    .set('Origin', 'https://portkey.example')
    .expect(200);
  const cookie = (response.headers['set-cookie'] as unknown as string[])[0];
  assert.match(cookie, /^__Host-portkey_session=/);
  assert.match(cookie, /Secure/);
  assert.doesNotMatch(cookie, /Domain=/);
});

test('writes reject foreign origins, missing CSRF, and malformed CSRF', async () => {
  await supertest(app).post('/api/session').set('Origin', 'https://attacker.example').expect(403);
  const client = await browser();
  await client.agent.post('/api/rooms').set('Origin', origin).send(input()).expect(403);
  await client.agent
    .post('/api/rooms')
    .set('Origin', origin)
    .set('X-CSRF-Token', 'é'.repeat(64))
    .send(input())
    .expect(403);
  await client.agent
    .post('/api/rooms')
    .set('Origin', 'https://attacker.example')
    .set('X-CSRF-Token', client.csrf)
    .send(input())
    .expect(403);
});

test('room input rejects missing titles, past dates, long lifetimes and role injection', async () => {
  const owner = await browser();
  await owner.post('/rooms', { ...input(), title: '   ' }).expect(422);
  await owner
    .post('/rooms', { ...input(), expiresAt: new Date(Date.now() - 1000).toISOString() })
    .expect(422);
  await owner
    .post('/rooms', { ...input(), expiresAt: new Date(Date.now() + 8 * 86400_000).toISOString() })
    .expect(422);
  await owner.post('/rooms', { ...input(), ownerId: 'attacker' }).expect(422);
  await owner.get('/rooms/not-a-uuid').expect(422);
});

test('rooms start as drafts, persist edits and appear only in the owner list', async () => {
  const owner = await browser();
  const outsider = await browser();
  const room = await createRoom(owner);
  assert.equal(room.status, 'draft');
  const edited = await owner
    .patch(`/rooms/${room.id}`, { ...input(), title: 'Updated workshop' })
    .expect(200);
  assert.equal(edited.body.title, 'Updated workshop');
  assert.equal((await owner.get('/rooms').expect(200)).body.length, 1);
  assert.deepEqual((await outsider.get('/rooms').expect(200)).body, []);
  await outsider.get(`/rooms/${room.id}`).expect(403);
  await outsider.patch(`/rooms/${room.id}`, input()).expect(403);
  await outsider.post(`/rooms/${room.id}/open`).expect(403);
  await outsider.post(`/rooms/${room.id}/close`).expect(403);
});

test('the join address reveals public details but never owner or membership records', async () => {
  const owner = await browser();
  const visitor = await browser();
  const room = await createRoom(owner);
  const response = await visitor.get(`/join/${room.joinCode}`).expect(200);
  assert.deepEqual(Object.keys(response.body).sort(), [
    'description',
    'expiresAt',
    'id',
    'isOwner',
    'membershipStatus',
    'organizerKeyFingerprint',
    'organizerPublicKey',
    'status',
    'title',
  ]);
  await visitor.get(`/rooms/${room.id}/members`).expect(403);
  await visitor.post(`/join/${room.joinCode}`, { label: 'Guest' }).expect(409);
});

test('join requests are idempotent and pending membership grants no access', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const first = await requestAdmission(participant, room);
  const second = await requestAdmission(participant, room);
  assert.equal(first.id, second.id);
  assert.equal(first.status, 'pending');
  await participant.get(`/rooms/${room.id}`).expect(403);
  assert.equal((await owner.get(`/rooms/${room.id}/members`).expect(200)).body.length, 1);
  await participant
    .patch(`/rooms/${room.id}/members/${first.id}`, { status: 'approved' })
    .expect(403);
});

test('approval grants participant access and removal immediately revokes it', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const member = await requestAdmission(participant, room);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  const admitted = await participant.get(`/rooms/${room.id}`).expect(200);
  assert.equal(admitted.body.role, 'participant');
  await participant.patch(`/rooms/${room.id}`, input()).expect(403);
  await participant.post(`/rooms/${room.id}/close`).expect(403);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'revoked' }).expect(200);
  await participant.get(`/rooms/${room.id}`).expect(403);
  await participant.post(`/join/${room.joinCode}`, { label: 'Another label' }).expect(403);
});

test('declined requests cannot self-reapprove or be approved through another room', async () => {
  const owner = await browser();
  const participant = await browser();
  const first = await createRoom(owner, true);
  const second = await createRoom(owner, true);
  const member = await requestAdmission(participant, first);
  await owner.patch(`/rooms/${second.id}/members/${member.id}`, { status: 'approved' }).expect(404);
  await owner.patch(`/rooms/${first.id}/members/${member.id}`, { status: 'denied' }).expect(200);
  await owner.patch(`/rooms/${first.id}/members/${member.id}`, { status: 'approved' }).expect(409);
  await participant.post(`/join/${first.joinCode}`, { label: 'Guest' }).expect(403);
});

test('closing is terminal and stops approved participants and join requests', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const member = await requestAdmission(participant, room);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  const closed = await owner.post(`/rooms/${room.id}/close`).expect(200);
  assert.equal(closed.body.status, 'closed');
  await participant.get(`/rooms/${room.id}`).expect(410);
  await participant.post(`/join/${room.joinCode}`, { label: 'Guest' }).expect(410);
  await owner.post(`/rooms/${room.id}/open`).expect(410);
  await owner.patch(`/rooms/${room.id}`, input()).expect(410);
  assert.equal((await owner.get(`/rooms/${room.id}`).expect(200)).body.status, 'closed');
});

test('expiry is enforced without a background worker and cannot be extended afterward', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const member = await requestAdmission(participant, room);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  await database.query(
    `UPDATE rooms SET created_at = clock_timestamp() - interval '2 days',
    expires_at = clock_timestamp() - interval '1 second' WHERE id = $1`,
    [room.id],
  );
  assert.equal(
    (await participant.get(`/join/${room.joinCode}`).expect(200)).body.status,
    'expired',
  );
  await participant.get(`/rooms/${room.id}`).expect(410);
  await participant.post(`/join/${room.joinCode}`, { label: 'Guest' }).expect(410);
  await owner.patch(`/rooms/${room.id}`, input()).expect(410);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'revoked' }).expect(410);
});

test('simultaneous closure and admission never leave an accessible closed room', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const [close, join] = await Promise.all([
    owner.post(`/rooms/${room.id}/close`),
    participant.post(`/join/${room.joinCode}`, { label: 'Late arrival' }),
  ]);
  assert.equal(close.status, 200);
  assert.ok([200, 410].includes(join.status));
  await participant.get(`/rooms/${room.id}`).expect(403);
  assert.equal((await participant.get(`/join/${room.joinCode}`).expect(200)).body.status, 'closed');
});

test('expired sessions do not authenticate', async () => {
  const client = await browser();
  await database.query(
    `UPDATE sessions SET created_at = clock_timestamp() - interval '1 hour',
    expires_at = clock_timestamp() - interval '1 second' WHERE token_hash = $1`,
    [createHash('sha256').update(client.token).digest('hex')],
  );
  await client.get('/rooms').expect(401);
});

test('database constraints and transaction rollback protect persisted state', async () => {
  const owner = await browser();
  const room = await createRoom(owner);
  await assert.rejects(
    database.query('UPDATE rooms SET status = $2 WHERE id = $1', [room.id, 'unknown']),
  );
  await assert.rejects(
    database.transaction(async (transaction) => {
      await transaction.query('UPDATE rooms SET title = $2 WHERE id = $1', [
        room.id,
        'Not committed',
      ]);
      throw new Error('Abort transaction');
    }),
    /Abort transaction/,
  );
  assert.equal((await owner.get(`/rooms/${room.id}`).expect(200)).body.title, 'Workshop');
});

test('migrations are idempotent and detect modified history', async () => {
  await migrate(database);
  const [row] = await database.query<{ checksum: string }>(
    'SELECT checksum FROM schema_migrations WHERE name = $1',
    ['001_initial.sql'],
  );
  await database.query('UPDATE schema_migrations SET checksum = $1 WHERE name = $2', [
    '0'.repeat(64),
    '001_initial.sql',
  ]);
  await assert.rejects(migrate(database), /Migration changed/);
  await database.query('UPDATE schema_migrations SET checksum = $1 WHERE name = $2', [
    row.checksum,
    '001_initial.sql',
  ]);
  await migrate(database);
});

test('a room template creates a fresh draft without copying membership or invitations', async () => {
  const owner = await browser();
  const participant = await browser();
  const original = await createRoom(owner, true);
  const member = await requestAdmission(participant, original);
  await owner
    .patch(`/rooms/${original.id}/members/${member.id}`, { status: 'approved' })
    .expect(200);
  const copy = (
    await owner
      .post(`/rooms/${original.id}/duplicate`, { expiresAt: input().expiresAt })
      .expect(201)
  ).body as Room;
  assert.equal(copy.title, original.title);
  assert.equal(copy.description, original.description);
  assert.equal(copy.status, 'draft');
  assert.notEqual(copy.id, original.id);
  assert.notEqual(copy.joinCode, original.joinCode);
  assert.deepEqual((await owner.get(`/rooms/${copy.id}/members`).expect(200)).body, []);
  await participant.get(`/rooms/${copy.id}`).expect(403);
  assert.equal((await participant.get(`/rooms/${original.id}`).expect(200)).body.status, 'open');
});

test('templates are owner-only and validate the new room independently', async () => {
  const owner = await browser();
  const outsider = await browser();
  const original = await createRoom(owner);
  await outsider
    .post(`/rooms/${original.id}/duplicate`, { expiresAt: input().expiresAt })
    .expect(403);
  await owner
    .post(`/rooms/${original.id}/duplicate`, {
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    })
    .expect(422);
  await owner
    .post(`/rooms/${original.id}/duplicate`, { expiresAt: input().expiresAt, status: 'open' })
    .expect(422);
  const copy = await owner
    .post(`/rooms/${original.id}/duplicate`, {
      ...input(),
      title: 'Next workshop',
      description: '',
    })
    .expect(201);
  assert.equal(copy.body.title, 'Next workshop');
  assert.equal(copy.body.description, '');
});

test('terminal rooms can be reused without reopening the original', async () => {
  const owner = await browser();
  const original = await createRoom(owner, true);
  await owner.post(`/rooms/${original.id}/close`).expect(200);
  const copy = await owner
    .post(`/rooms/${original.id}/duplicate`, { expiresAt: input().expiresAt })
    .expect(201);
  assert.equal(copy.body.status, 'draft');
  assert.equal((await owner.get(`/rooms/${original.id}`).expect(200)).body.status, 'closed');
  await database.query(
    `UPDATE rooms SET created_at = clock_timestamp() - interval '2 days',
    expires_at = clock_timestamp() - interval '1 second' WHERE id = $1`,
    [copy.body.id],
  );
  const next = await owner
    .post(`/rooms/${copy.body.id}/duplicate`, { expiresAt: input().expiresAt })
    .expect(201);
  assert.equal(next.body.status, 'draft');
  assert.equal((await owner.get(`/rooms/${copy.body.id}`).expect(200)).body.status, 'expired');
});

test('activity records successful actions without duplicating repeated requests or unchanged edits', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner);
  await owner
    .patch(`/rooms/${room.id}`, {
      title: room.title,
      description: room.description,
      expiresAt: room.expiresAt,
    })
    .expect(200);
  await owner.post(`/rooms/${room.id}/open`).expect(200);
  const member = await requestAdmission(participant, room);
  await requestAdmission(participant, room);
  await owner
    .patch(`/rooms/${room.id}`, {
      title: 'Revised title',
      description: room.description,
      expiresAt: room.expiresAt,
    })
    .expect(200);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'revoked' }).expect(200);
  await owner.post(`/rooms/${room.id}/close`).expect(200);
  const page = (await owner.get(`/rooms/${room.id}/activity`).expect(200)).body as ActivityPage;
  assert.deepEqual(
    page.events.map((event) => event.kind),
    [
      'room_closed',
      'member_revoked',
      'member_approved',
      'room_updated',
      'join_requested',
      'room_opened',
      'room_created',
    ],
  );
  assert.deepEqual(page.events.find((event) => event.kind === 'room_updated')!.changedFields, [
    'title',
  ]);
  assert.equal(
    page.events.find((event) => event.kind === 'join_requested')!.memberLabel,
    'Team Cedar',
  );
  for (const event of page.events) {
    assert.deepEqual(Object.keys(event).sort(), [
      'changedFields',
      'createdAt',
      'id',
      'kind',
      'memberLabel',
    ]);
    assert.ok(!Number.isNaN(Date.parse(event.createdAt)));
  }
  assert.ok(!JSON.stringify(page).includes(owner.token));
  assert.ok(!JSON.stringify(page).includes('Revised title'));
});

test('activity is owner-only, room-isolated and remains readable after expiry', async () => {
  const owner = await browser();
  const outsider = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const member = await requestAdmission(participant, room);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  await participant.get(`/rooms/${room.id}/activity`).expect(403);
  await outsider.get(`/rooms/${room.id}/activity`).expect(403);
  await supertest(app).get(`/api/rooms/${room.id}/activity`).expect(401);
  const another = await createRoom(owner);
  assert.equal(
    (await owner.get(`/rooms/${another.id}/activity`).expect(200)).body.events.length,
    1,
  );
  await database.query(
    `UPDATE rooms SET created_at = clock_timestamp() - interval '2 days',
    expires_at = clock_timestamp() - interval '1 second' WHERE id = $1`,
    [room.id],
  );
  assert.equal((await owner.get(`/rooms/${room.id}/activity`).expect(200)).body.events.length, 4);
});

test('declined requests and template creation have distinct activity', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await createRoom(owner, true);
  const member = await requestAdmission(participant, room);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'denied' }).expect(200);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(409);
  const original = (await owner.get(`/rooms/${room.id}/activity`).expect(200)).body as ActivityPage;
  assert.equal(original.events[0].kind, 'member_denied');
  const copy = (
    await owner.post(`/rooms/${room.id}/duplicate`, { expiresAt: input().expiresAt }).expect(201)
  ).body as Room;
  const copied = (await owner.get(`/rooms/${copy.id}/activity`).expect(200)).body as ActivityPage;
  assert.deepEqual(
    copied.events.map((event) => event.kind),
    ['room_duplicated'],
  );
  assert.equal(
    (await owner.get(`/rooms/${room.id}/activity`).expect(200)).body.events.length,
    original.events.length,
  );
});

test('keyset activity pages stay stable when newer actions arrive', async () => {
  const owner = await browser();
  const room = await createRoom(owner);
  for (let index = 0; index < 44; index++) await recordActivity(database, room.id, 'room_opened');
  const first = (await owner.get(`/rooms/${room.id}/activity`).expect(200)).body as ActivityPage;
  assert.equal(first.events.length, 20);
  await recordActivity(database, room.id, 'room_closed');
  const second = (
    await owner.get(`/rooms/${room.id}/activity?before=${first.nextCursor}`).expect(200)
  ).body as ActivityPage;
  const third = (
    await owner.get(`/rooms/${room.id}/activity?before=${second.nextCursor}`).expect(200)
  ).body as ActivityPage;
  const events = [...first.events, ...second.events, ...third.events];
  assert.equal(new Set(events.map((event) => event.id)).size, 45);
  assert.ok(events.every((event, index) => index === 0 || BigInt(events[index - 1].id) > BigInt(event.id)));
  assert.equal(third.nextCursor, null);
  assert.equal(third.events.at(-1)!.kind, 'room_created');
  for (const value of ['abc', '0', '-1', '1.5', '9223372036854775808', '99999999999999999999999']) {
    await owner.get(`/rooms/${room.id}/activity?before=${value}`).expect(422);
  }
  await owner.get(`/rooms/${room.id}/activity?limit=1000`).expect(422);
});

test('room changes roll back if activity cannot be recorded', async (context) => {
  context.mock.method(console, 'error', () => {});
  const owner = await browser();
  const room = await createRoom(owner);
  await database.exec(
    "ALTER TABLE room_activity ADD CONSTRAINT test_activity_failure CHECK (kind <> 'room_opened') NOT VALID",
  );
  try {
    await owner.post(`/rooms/${room.id}/open`).expect(500);
    assert.equal((await owner.get(`/rooms/${room.id}`).expect(200)).body.status, 'draft');
    assert.equal((await owner.get(`/rooms/${room.id}/activity`).expect(200)).body.events.length, 1);
  } finally {
    await database.exec('ALTER TABLE room_activity DROP CONSTRAINT test_activity_failure');
  }
  const before = (await owner.get('/rooms').expect(200)).body.length;
  await database.exec(
    "ALTER TABLE room_activity ADD CONSTRAINT test_activity_failure CHECK (kind <> 'room_created') NOT VALID",
  );
  try {
    await owner.post('/rooms', input()).expect(500);
    assert.equal((await owner.get('/rooms').expect(200)).body.length, before);
  } finally {
    await database.exec('ALTER TABLE room_activity DROP CONSTRAINT test_activity_failure');
  }
});

test('embedded PostgreSQL persists rooms across restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'portkey-test-'));
  let persistent = await openDatabase({ dataDir: join(directory, 'db') });
  try {
    await migrate(persistent);
    await persistent.query(
      `INSERT INTO sessions (id, token_hash, expires_at)
      VALUES ('00000000-0000-4000-8000-000000000001', $1, clock_timestamp() + interval '1 day')`,
      ['a'.repeat(64)],
    );
    await persistent.query(`INSERT INTO rooms (id, owner_id, join_code, title, expires_at)
      VALUES ('00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000001',
      'abcdefghijklmnop', 'Saved room', clock_timestamp() + interval '1 hour')`);
    await recordActivity(persistent, '00000000-0000-4000-8000-000000000002', 'room_created');
    await persistent.close();
    persistent = await openDatabase({ dataDir: join(directory, 'db') });
    await migrate(persistent);
    const [row] = await persistent.query<{ title: string }>('SELECT title FROM rooms');
    assert.equal(row.title, 'Saved room');
    assert.equal(
      (await readActivity(persistent, '00000000-0000-4000-8000-000000000002')).events[0].kind,
      'room_created',
    );
  } finally {
    await persistent.close();
    await rm(directory, { recursive: true, force: true });
  }
});
