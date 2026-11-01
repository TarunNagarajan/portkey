import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import type { Express } from 'express';
import {
  CipherSuite,
  Aes256Gcm,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from '@hpke/core';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from './database.js';
import { runFileCleanupPass } from '../server/cleanup.js';
import { migrate } from '../server/migrations.js';
import type { Room } from '../shared/rooms.js';

const origin = 'http://localhost:5173';
const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});
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
  const response = await agent
    .post('/api/session')
    .set('Origin', origin)
    .expect(200);
  const csrf = response.body.csrfToken as string;
  return {
    agent,
    csrf,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) =>
      agent
        .post(`/api${path}`)
        .set('Origin', origin)
        .set('X-CSRF-Token', csrf)
        .send(body),
    patch: (path: string, body: object) =>
      agent
        .patch(`/api${path}`)
        .set('Origin', origin)
        .set('X-CSRF-Token', csrf)
        .send(body),
    put: (path: string, body: Buffer | object, type?: string) => {
      const request = agent
        .put(`/api${path}`)
        .set('Origin', origin)
        .set('X-CSRF-Token', csrf);
      return type
        ? request.set('Content-Type', type).send(body as Buffer)
        : request.send(body as object);
    },
  };
}

async function createPublicKey() {
  const keys = await suite.kem.generateKeyPair();
  return new Uint8Array(await suite.kem.serializePublicKey(keys.publicKey));
}
const base64 = (value: Uint8Array) => Buffer.from(value).toString('base64');
const sha256Hex = (value: Buffer) =>
  createHash('sha256').update(value).digest('hex');

function envelope() {
  return {
    enc: base64(Buffer.alloc(65, 3)),
    ciphertext: base64(Buffer.alloc(48, 4)),
  };
}

async function publishFile(
  owner: Awaited<ReturnType<typeof browser>>,
  room: Room,
  recipientIds: string[],
  roomFingerprint?: string,
) {
  const fileId = randomUUID();
  const descriptor = Buffer.alloc(96, 9);
  await owner.post(`/rooms/${room.id}/files`, { fileId }).expect(201);
  await owner
    .put(`/rooms/${room.id}/files/${fileId}/metadata`, {
      descriptor: descriptor.toString('base64'),
      ...(roomFingerprint ? { roomEnvelope: { fingerprint: roomFingerprint, ...envelope() } } : {}),
      envelopes: recipientIds.map((recipientId) => ({
        recipientId,
        ...envelope(),
      })),
    })
    .expect(204);
  const chunks = [Buffer.alloc(40, 1), Buffer.alloc(33, 2)];
  for (const [index, ciphertext] of chunks.entries())
    await owner
      .put(
        `/rooms/${room.id}/files/${fileId}/chunks/${index}`,
        ciphertext,
        'application/octet-stream',
      )
      .expect(201);
  const manifest = createHash('sha256').update(descriptor);
  for (const ciphertext of chunks)
    manifest.update(Buffer.from(sha256Hex(ciphertext), 'hex'));
  const completed = await owner
    .post(`/rooms/${room.id}/files/${fileId}/complete`, {
      chunkCount: chunks.length,
      manifestSha256: manifest.digest('hex'),
    })
    .expect(200);
  return { fileId, chunks, receipt: completed.body.receipt };
}

async function approvedRoom(geo = false) {
  const owner = await browser();
  const participant = await browser();
  const created = (
    await owner
      .post('/rooms', {
        title: 'Distribution room',
        description: '',
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      })
      .expect(201)
  ).body as Room;
  if (geo) await owner.post(`/rooms/${created.id}/geo`, {
    lat: 17.9689, lng: 79.5941, radiusM: 150, label: 'Campus', source: 'device',
  }).expect(200);
  const room = (
    await owner.post(`/rooms/${created.id}/open`).expect(200)
  ).body as Room;
  await participant
    .post(`/join/${room.joinCode}`, { label: 'Student', ...(geo ? {
      lat: 17.9689, lng: 79.5941, accuracyM: 10, timestamp: new Date().toISOString(),
    } : {}) })
    .expect(200);
  const members = await owner.get(`/rooms/${room.id}/members`).expect(200);
  await owner
    .patch(`/rooms/${room.id}/members/${members.body[0].id}`, {
      status: 'approved',
    })
    .expect(200);
  const ownerKey = await createPublicKey();
  await owner
    .post(`/rooms/${room.id}/keys/owner`, {
      publicKey: base64(ownerKey),
    })
    .expect(201);
  const participantKey = await createPublicKey();
  await participant
    .post(`/rooms/${room.id}/keys/participant`, {
      publicKey: base64(participantKey),
    })
    .expect(201);
  return { owner, participant, room };
}

test('keys are role-bound, immutable and required before publishing', async () => {
  const { owner, participant, room } = await approvedRoom();
  const outsiderKey = await createPublicKey();

  await participant
    .post(`/rooms/${room.id}/keys/owner`, { publicKey: base64(outsiderKey) })
    .expect(403);
  await owner
    .post(`/rooms/${room.id}/keys/participant`, { publicKey: base64(outsiderKey) })
    .expect(403);

  const fileId = randomUUID();
  await owner.post(`/rooms/${room.id}/files`, { fileId }).expect(201);
  await owner
    .put(`/rooms/${room.id}/files/${fileId}/metadata`, {
      descriptor: Buffer.alloc(96, 9).toString('base64'),
      envelopes: [{ recipientId: randomUUID(), ...envelope() }],
    })
    .expect(422);
});

test('the organizer key is immutable across registrations', async () => {
  const { owner, participant, room } = await approvedRoom();
  const replacement = await createPublicKey();

  const registered = await owner
    .get(`/rooms/${room.id}/files/keys`)
    .expect(200);
  await owner
    .post(`/rooms/${room.id}/keys/owner`, {
      publicKey: base64(replacement),
    })
    .expect(409, {
      error: {
        code: 'KEY_IMMUTABLE',
        message: 'The organizer key is already registered and cannot be replaced.',
      },
    });
  const participantReplacement = await createPublicKey();
  await participant
    .post(`/rooms/${room.id}/keys/participant`, {
      publicKey: base64(participantReplacement),
    })
    .expect(409, {
      error: {
        code: 'KEY_IMMUTABLE',
        message: 'This browser key is already registered for the room.',
      },
    });
  const after = await owner.get(`/rooms/${room.id}/files/keys`).expect(200);
  assert.equal(after.body.ownerFingerprint, registered.body.ownerFingerprint);
  assert.equal(
    after.body.recipients[0].fingerprint,
    registered.body.recipients[0].fingerprint,
  );
});

test('organizer publishes a file that only approved recipients can read', async () => {
  const { owner, participant, room } = await approvedRoom();
  const outsider = await browser();

  const keys = await owner.get(`/rooms/${room.id}/files/keys`).expect(200);
  assert.equal(keys.body.recipients.length, 1);
  assert.equal(keys.body.recipients[0].label, 'Student');
  assert.equal(typeof keys.body.ownerRecipientId, 'string');

  const { fileId, chunks } = await publishFile(owner, room, [
    keys.body.ownerRecipientId,
    keys.body.recipients[0].id,
  ]);

  const ownerList = await owner.get(`/rooms/${room.id}/files`).expect(200);
  assert.equal(ownerList.body.files.length, 1);
  assert.equal(ownerList.body.files[0].id, fileId);
  assert.equal(ownerList.body.files[0].chunkCount, chunks.length);

  const participantList = await participant
    .get(`/rooms/${room.id}/files`)
    .expect(200);
  assert.equal(participantList.body.files.length, 1);

  const chunk = await participant
    .get(`/rooms/${room.id}/files/${fileId}/chunks/0`)
    .expect(200);
  assert.equal(chunk.body.length, chunks[0].length);
  assert.equal(
    chunk.headers['x-ciphertext-sha256'],
    sha256Hex(chunks[0]),
  );

  await outsider.get(`/rooms/${room.id}/files`).expect(403);
  await outsider
    .get(`/rooms/${room.id}/files/${fileId}/chunks/0`)
    .expect(403);

  const activity = await owner
    .get(`/rooms/${room.id}/activity`)
    .expect(200);
  assert.ok(
    activity.body.events.some(
      (event: { kind: string }) => event.kind === 'file_published',
    ),
  );
});

test('metadata must name eligible recipients and keep an organizer copy', async () => {
  const { owner, room } = await approvedRoom();
  const fileId = randomUUID();
  await owner.post(`/rooms/${room.id}/files`, { fileId }).expect(201);
  const descriptor = Buffer.alloc(96, 9).toString('base64');

  await owner
    .put(`/rooms/${room.id}/files/${fileId}/metadata`, {
      descriptor,
      envelopes: [{ recipientId: randomUUID(), ...envelope() }],
    })
    .expect(422);

  const keys = await owner.get(`/rooms/${room.id}/files/keys`).expect(200);
  await owner
    .put(`/rooms/${room.id}/files/${fileId}/metadata`, {
      descriptor,
      envelopes: [
        { recipientId: keys.body.recipients[0].id, ...envelope() },
      ],
    })
    .expect(422);

  await owner
    .put(`/rooms/${room.id}/files/${fileId}/metadata`, {
      descriptor,
      envelopes: [
        { recipientId: keys.body.ownerRecipientId, ...envelope() },
        { recipientId: keys.body.recipients[0].id, ...envelope() },
      ],
    })
    .expect(204);
});

test('only the organizer can start, chunk and finalize a distribution', async () => {
  const { owner, participant, room } = await approvedRoom();
  const fileId = randomUUID();
  await participant.post(`/rooms/${room.id}/files`, { fileId }).expect(403);
  await owner.post(`/rooms/${room.id}/files`, { fileId }).expect(201);
  await participant
    .put(`/rooms/${room.id}/files/${fileId}/metadata`, {
      descriptor: Buffer.alloc(96, 9).toString('base64'),
      envelopes: [{ recipientId: randomUUID(), ...envelope() }],
    })
    .expect(403);
  await participant
    .put(
      `/rooms/${room.id}/files/${fileId}/chunks/0`,
      Buffer.alloc(40, 1),
      'application/octet-stream',
    )
    .expect(403);
});


test('direct file and key APIs enforce fresh inside location, revocation, and closure', async () => {
  const { owner, participant, room } = await approvedRoom(true);
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const { fileId } = await publishFile(owner, room, [keys.ownerRecipientId, keys.recipients[0].id]);
  const publicKey = base64(await createPublicKey());
  const assertBlocked = async (code: string) => {
    for (const path of [`/rooms/${room.id}`, `/rooms/${room.id}/files`,
      `/rooms/${room.id}/files/keys`, `/rooms/${room.id}/files/${fileId}/chunks/0`]) {
      const response = await participant.get(path).expect(403);
      assert.equal(response.body.error.code, code);
    }
    const response = await participant.post(`/rooms/${room.id}/keys/participant`, { publicKey }).expect(403);
    assert.equal(response.body.error.code, code);
  };
  await database.query("UPDATE memberships SET last_checked_at = clock_timestamp() - interval '6 minutes' WHERE room_id = $1", [room.id]);
  await assertBlocked('GEO_STALE');
  await participant.post(`/rooms/${room.id}/position`, {
    lat: 17.385, lng: 78.4867, accuracyM: 10, timestamp: new Date().toISOString(),
  }).expect(200);
  await assertBlocked('GEO_OUTSIDE');
  await participant.post(`/rooms/${room.id}/position`, {
    lat: 17.9689, lng: 79.5941, accuracyM: 10, timestamp: new Date().toISOString(),
  }).expect(200);
  await participant.get(`/rooms/${room.id}/files`).expect(200);
  await participant.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(200);
  const members = (await owner.get(`/rooms/${room.id}/members`).expect(200)).body;
  await owner.patch(`/rooms/${room.id}/members/${members[0].id}`, { status: 'revoked' }).expect(200);
  await assertBlocked('ADMISSION_REQUIRED');
  await owner.post(`/rooms/${room.id}/close`).expect(200);
  await owner.get(`/rooms/${room.id}/files`).expect(410);
  await participant.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(410);
});

test('expiry cleanup cascades ciphertext and envelopes exactly once, retaining history', async () => {
  const { owner, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const { fileId } = await publishFile(owner, room, [keys.ownerRecipientId]);
  await database.query("UPDATE rooms SET created_at = clock_timestamp() - interval '2 hours', expires_at = clock_timestamp() - interval '1 second' WHERE id = $1", [room.id]);
  await owner.get(`/rooms/${room.id}/files`).expect(410);
  const result = await runFileCleanupPass(database);
  assert.equal(result.roomsCompleted, 1);
  assert.equal(result.filesDeleted, 1);
  for (const table of ['room_files', 'room_file_chunks', 'room_file_envelopes']) {
    const column = table === 'room_files' ? 'id' : 'file_id';
    const rows = await database.query(`SELECT * FROM ${table} WHERE ${column} = $1`, [fileId]);
    assert.equal(rows.length, 0);
  }
  const [stored] = await database.query<{ files_purged_at: Date }>('SELECT files_purged_at FROM rooms WHERE id = $1', [room.id]);
  assert.ok(stored.files_purged_at);
  assert.equal((await runFileCleanupPass(database)).roomsCompleted, 0);
  const history = (await owner.get(`/rooms/${room.id}/activity`).expect(200)).body.events;
  assert.equal(history.filter((event: { kind: string }) => event.kind === 'files_purged').length, 1);
});

test('stale uploads reclaim pending slots and byte usage without deleting published files', async () => {
  const { owner, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const published = await publishFile(owner, room, [keys.ownerRecipientId]);
  const staleId = randomUUID();
  await owner.post(`/rooms/${room.id}/files`, { fileId: staleId }).expect(201);
  await owner.put(`/rooms/${room.id}/files/${staleId}/metadata`, {
    descriptor: Buffer.alloc(96).toString('base64'), envelopes: [{ recipientId: keys.ownerRecipientId, ...envelope() }],
  }).expect(204);
  await owner.put(`/rooms/${room.id}/files/${staleId}/chunks/0`, Buffer.alloc(40), 'application/octet-stream').expect(201);
  await database.query("UPDATE room_files SET created_at = clock_timestamp() - interval '25 hours' WHERE id = $1", [staleId]);
  const result = await runFileCleanupPass(database);
  assert.equal(result.staleUploadsDeleted, 1);
  assert.equal(result.staleBytesReclaimed, 40);
  const files = (await owner.get(`/rooms/${room.id}/files`).expect(200)).body.files;
  assert.deepEqual(files.map((file: { id: string }) => file.id), [published.fileId]);
  assert.equal((await runFileCleanupPass(database)).staleUploadsDeleted, 0);
});

test('chunk retries are immutable and completion rejects a corrupted manifest', async () => {
  const { owner, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const fileId = randomUUID();
  await owner.post(`/rooms/${room.id}/files`, { fileId }).expect(201);
  await owner.put(`/rooms/${room.id}/files/${fileId}/metadata`, {
    descriptor: Buffer.alloc(96).toString('base64'), envelopes: [{ recipientId: keys.ownerRecipientId, ...envelope() }],
  }).expect(204);
  await owner.put(`/rooms/${room.id}/files/${fileId}/metadata`, {
    descriptor: Buffer.alloc(96).toString('base64'), envelopes: [{ recipientId: keys.ownerRecipientId, ...envelope() }],
    recipientFingerprints: { [keys.ownerRecipientId]: '0'.repeat(64) },
  }).expect(409);
  const path = `/rooms/${room.id}/files/${fileId}/chunks/0`;
  await owner.put(path, Buffer.alloc(40, 1), 'application/octet-stream').expect(201);
  await owner.put(path, Buffer.alloc(40, 1), 'application/octet-stream').expect(200);
  await owner.put(path, Buffer.alloc(40, 2), 'application/octet-stream').expect(409);
  await owner.post(`/rooms/${room.id}/files/${fileId}/complete`, { chunkCount: 1, manifestSha256: '0'.repeat(64) }).expect(422);
  const [stored] = await database.query<{ chunk_count: number; encrypted_bytes: string }>('SELECT chunk_count, encrypted_bytes FROM room_files WHERE id = $1', [fileId]);
  assert.equal(stored.chunk_count, 1);
  assert.equal(Number(stored.encrypted_bytes), 40);
});

test('a full-size chunk sequence fits the enabled rate limit and session creation stays IP bounded', async () => {
  const { owner, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const fileId = randomUUID();
  await owner.post(`/rooms/${room.id}/files`, { fileId }).expect(201);
  await owner.put(`/rooms/${room.id}/files/${fileId}/metadata`, {
    descriptor: Buffer.alloc(96).toString('base64'), envelopes: [{ recipientId: keys.ownerRecipientId, ...envelope() }],
  }).expect(204);
  // Reuse the existing session against an app with real limiter middleware.
  // Install a known token for this test's existing owner session.
  const token = 'L'.repeat(43);
  const ownerId = keys.ownerRecipientId;
  await database.query('UPDATE sessions SET token_hash = $2 WHERE id = $1', [ownerId, sha256Hex(Buffer.from(token))]);
  const limited = createApp(database, { origin, secure: false });
  const csrf = sha256Hex(Buffer.from(`csrf:${token}`));
  for (let index = 0; index < 250; index++) {
    await supertest(limited).put(`/api/rooms/${room.id}/files/${fileId}/chunks/${index}`)
      .set('Cookie', `portkey_session=${token}`).set('Origin', origin).set('X-CSRF-Token', csrf)
      .set('Content-Type', 'application/octet-stream').send(Buffer.alloc(16)).expect(201);
  }
  for (let index = 0; index < 30; index++) await supertest(limited).post('/api/session').set('Origin', origin).expect(200);
  const denied = await supertest(limited).post('/api/session').set('Origin', origin).expect(429);
  assert.equal(denied.body.error.code, 'RATE_LIMITED');
});

test('file-count and room-byte quotas reject new uploads without allocating large ciphertext', async () => {
  const { owner, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const seedCompleted = (ids: string[], bytes: number) => database.query(
    `INSERT INTO room_files (id, room_id, owner_id, status, encrypted_bytes, completed_at, manifest_sha256)
     SELECT id, $1, $2, 'complete', $4, clock_timestamp(), $5 FROM unnest($3::uuid[]) AS id`,
    [room.id, keys.ownerRecipientId, ids, bytes, '0'.repeat(64)],
  );
  await seedCompleted(Array.from({ length: 1000 }, () => randomUUID()), 0);
  const countLimit = await owner.post(`/rooms/${room.id}/files`, { fileId: randomUUID() }).expect(413);
  assert.equal(countLimit.body.error.code, 'OBJECT_LIMIT');
  await database.query('DELETE FROM room_files WHERE room_id = $1', [room.id]);
  await seedCompleted(Array.from({ length: 21 }, () => randomUUID()), 250 * 1024 * 1024);
  const byteLimit = await owner.post(`/rooms/${room.id}/files`, { fileId: randomUUID() }).expect(413);
  assert.equal(byteLimit.body.error.code, 'ROOM_QUOTA');
});

test('late recipients receive explicit grants and rotations require every existing file envelope', async () => {
  const { owner, participant, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`)).body;
  const { fileId } = await publishFile(owner, room, [keys.ownerRecipientId]);
  assert.equal((await participant.get(`/rooms/${room.id}/files`)).body.files.length, 0);
  const recipient = keys.recipients[0];
  await participant.post(`/rooms/${room.id}/files/grants`, { recipientId: recipient.id, fingerprint: recipient.fingerprint, envelopes: [] }).expect(403);
  await owner.post(`/rooms/${room.id}/files/grants`, { recipientId: recipient.id, fingerprint: '0'.repeat(64), envelopes: [{ fileId, ...envelope() }] }).expect(409);
  await owner.post(`/rooms/${room.id}/files/grants`, { recipientId: recipient.id, fingerprint: recipient.fingerprint, envelopes: [{ fileId, ...envelope() }] }).expect(204);
  assert.equal((await participant.get(`/rooms/${room.id}/files`).expect(200)).body.files.length, 1);
  const publicKey = base64(await createPublicKey());
  await participant.post(`/rooms/${room.id}/keys/rotate`, { publicKey, expectedFingerprint: recipient.fingerprint, envelopes: [] }).expect(422);
  const rotated = await participant.post(`/rooms/${room.id}/keys/rotate`, { publicKey, expectedFingerprint: recipient.fingerprint, envelopes: [{ fileId, ...envelope() }] }).expect(200);
  assert.notEqual(rotated.body.fingerprint, recipient.fingerprint);
  await participant.post(`/rooms/${room.id}/keys/rotate`, { publicKey, expectedFingerprint: recipient.fingerprint, envelopes: [{ fileId, ...envelope() }] }).expect(409);
});

test('ownership recovery codes rotate, transfer file authority and are single-use', async () => {
  const { owner, room } = await approvedRoom();
  const keys = (await owner.get(`/rooms/${room.id}/files/keys`)).body;
  const { fileId } = await publishFile(owner, room, [keys.ownerRecipientId]);
  const next = await browser();
  await next.post(`/rooms/${room.id}/recovery`).expect(403);
  const oldCode = (await owner.post(`/rooms/${room.id}/recovery`).expect(200)).body.recoveryCode;
  const code = (await owner.post(`/rooms/${room.id}/recovery`).expect(200)).body.recoveryCode;
  await next.post('/rooms/recover', { recoveryCode: oldCode }).expect(403);
  await next.post('/rooms/recover', { recoveryCode: code }).expect(200);
  await owner.get(`/rooms/${room.id}/members`).expect(403);
  assert.equal((await next.get(`/rooms/${room.id}`).expect(200)).body.role, 'owner');
  await next.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(200);
  await next.post('/rooms/recover', { recoveryCode: code }).expect(403);
});

test('rate limits coordinate across independent API instances', async () => {
  const first = createApp(database, { origin, secure: false });
  const second = createApp(database, { origin, secure: false });
  await database.query("DELETE FROM request_budgets WHERE key LIKE 'sessions:%'");
  for (let i = 0; i < 30; i++) await supertest(i % 2 ? first : second).post('/api/session').set('Origin', origin).expect(200);
  await supertest(second).post('/api/session').set('Origin', origin).expect(429);
});


test('room-wide files are readable by every current and future approved member without individual envelopes', async () => {
  const { owner, participant, room } = await approvedRoom(true);
  const publicKey = base64(await createPublicKey());
  const registered = (await owner.post(`/rooms/${room.id}/keys/room-access`, { publicKey }).expect(201)).body;
  await participant.post(`/rooms/${room.id}/keys/room-access`, { publicKey }).expect(403);
  await owner.post(`/rooms/${room.id}/keys/room-access`, { publicKey: base64(await createPublicKey()) }).expect(409);
  const info = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const { fileId } = await publishFile(owner, room, [info.ownerRecipientId], registered.fingerprint);
  const current = (await participant.get(`/rooms/${room.id}/files`).expect(200)).body;
  assert.equal(current.files[0].envelopeKind, 'room');
  assert.equal(current.files[0].roomShared, true);
  const newcomer = await browser();
  await newcomer.get(`/rooms/${room.id}/files`).expect(403);
  await newcomer.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(403);
  const joined = (await newcomer.post(`/join/${room.joinCode}`, { label: 'Late arrival', lat: 17.9689, lng: 79.5941, accuracyM: 10, timestamp: new Date().toISOString() }).expect(200)).body;
  await newcomer.get(`/rooms/${room.id}/files`).expect(403);
  await owner.patch(`/rooms/${room.id}/members/${joined.id}`, { status: 'approved' }).expect(200);
  // No individual browser key registration and no owner grant is needed.
  const files = (await newcomer.get(`/rooms/${room.id}/files`).expect(200)).body.files;
  assert.equal(files[0].id, fileId); assert.equal(files[0].envelopeKind, 'room');
  await newcomer.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(200);
  const personal = await database.query('SELECT 1 FROM room_file_envelopes WHERE file_id = $1 AND recipient_id = $2', [fileId, (await database.query<{ session_id: string }>('SELECT session_id FROM memberships WHERE id = $1', [joined.id]))[0].session_id]);
  assert.equal(personal.length, 0);
  await database.query("UPDATE memberships SET last_checked_at = clock_timestamp() - interval '6 minutes' WHERE id = $1", [joined.id]);
  await newcomer.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(403);
  await newcomer.post(`/rooms/${room.id}/position`, { lat: 17.9689, lng: 79.5941, accuracyM: 10, timestamp: new Date().toISOString() }).expect(200);
  await newcomer.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(200);
  await owner.patch(`/rooms/${room.id}/members/${joined.id}`, { status: 'revoked' }).expect(200);
  await newcomer.get(`/rooms/${room.id}/files`).expect(403);
  await newcomer.get(`/rooms/${room.id}/files/${fileId}/chunks/0`).expect(403);
});

test('the owner upgrades old publications to room access without changing ciphertext or manifests', async () => {
  const { owner, participant, room } = await approvedRoom();
  const info = (await owner.get(`/rooms/${room.id}/files/keys`).expect(200)).body;
  const { fileId } = await publishFile(owner, room, [info.ownerRecipientId]);
  const before = (await owner.get(`/rooms/${room.id}/files`).expect(200)).body.files[0];
  const publicKey = base64(await createPublicKey());
  const { fingerprint } = (await owner.post(`/rooms/${room.id}/keys/room-access`, { publicKey }).expect(201)).body;
  const body = { fingerprint, envelopes: [{ fileId, ...envelope() }] };
  await participant.post(`/rooms/${room.id}/files/room-access`, body).expect(403);
  await owner.post(`/rooms/${room.id}/files/room-access`, body).expect(204);
  await owner.post(`/rooms/${room.id}/files/room-access`, body).expect(204);
  const after = (await participant.get(`/rooms/${room.id}/files`).expect(200)).body.files[0];
  assert.equal(after.id, fileId); assert.equal(after.manifestSha256, before.manifestSha256);
  assert.equal(after.chunkCount, before.chunkCount); assert.equal(after.envelopeKind, 'room');
  const nextId = randomUUID();
  await owner.post(`/rooms/${room.id}/files`, { fileId: nextId }).expect(201);
  const missing = await owner.put(`/rooms/${room.id}/files/${nextId}/metadata`, { descriptor: Buffer.alloc(96).toString('base64'), envelopes: [{ recipientId: info.ownerRecipientId, ...envelope() }] }).expect(409);
  assert.equal(missing.body.error.code, 'ROOM_ACCESS_REQUIRED');
});
