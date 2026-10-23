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
import { openDatabase, type Database } from '../server/database.js';
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
    delete: (path: string) =>
      agent
        .delete(`/api${path}`)
        .set('Origin', origin)
        .set('X-CSRF-Token', csrf),
    put: (path: string, body: Buffer | object, type?: string) => {
      const req = agent
        .put(`/api${path}`)
        .set('Origin', origin)
        .set('X-CSRF-Token', csrf);
      return type
        ? req.set('Content-Type', type).send(body as Buffer)
        : req.send(body as object);
    },
  };
}

const roomInput = () => ({
  title: 'Inbox room',
  description: '',
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
});
async function makeRoom(
  owner: Awaited<ReturnType<typeof browser>>,
): Promise<Room> {
  const created = (await owner.post('/rooms', roomInput()).expect(201))
    .body as Room;
  return (await owner.post(`/rooms/${created.id}/open`).expect(200))
    .body as Room;
}
async function createPublicKey() {
  const keys = await suite.kem.generateKeyPair();
  return new Uint8Array(await suite.kem.serializePublicKey(keys.publicKey));
}
const base64 = (value: Uint8Array) => Buffer.from(value).toString('base64');
const sha256 = (value: Buffer) => createHash('sha256').update(value).digest();

test('private submission keys are immutable and completed chunks are visible only to owner and submitter', async () => {
  const owner = await browser();
  const participant = await browser();
  const outsider = await browser();
  const room = await makeRoom(owner);
  await participant
    .post(`/join/${room.joinCode}`, { label: 'Participant' })
    .expect(200);
  const members = await owner.get(`/rooms/${room.id}/members`).expect(200);
  await owner
    .patch(`/rooms/${room.id}/members/${members.body[0].id}`, {
      status: 'approved',
    })
    .expect(200);
  const ownerKey = await createPublicKey();
  const participantKey = await createPublicKey();
  await owner
    .post(`/rooms/${room.id}/submissions/owner-key`, {
      publicKey: base64(ownerKey),
    })
    .expect(201);
  await owner
    .post(`/rooms/${room.id}/submissions/owner-key`, {
      publicKey: base64(await createPublicKey()),
    })
    .expect(409);
  await participant
    .post(`/rooms/${room.id}/submissions/submitter-key`, {
      publicKey: base64(participantKey),
    })
    .expect(201);
  await outsider
    .post(`/rooms/${room.id}/submissions/submitter-key`, {
      publicKey: base64(await createPublicKey()),
    })
    .expect(403);
  await outsider.get(`/rooms/${room.id}/submissions`).expect(403);
  const uploadId = randomUUID();
  const created = await participant
    .post(`/rooms/${room.id}/submissions`, { uploadId })
    .expect(201);
  assert.equal(
    (
      await participant
        .post(`/rooms/${room.id}/submissions`, { uploadId })
        .expect(201)
    ).body.id,
    created.body.id,
  );
  const descriptor = Buffer.alloc(69, 7);
  const enc = Buffer.alloc(65, 4);
  const envelope = {
    enc: enc.toString('base64'),
    ciphertext: Buffer.alloc(16, 8).toString('base64'),
  };
  const metadata = {
    descriptor: descriptor.toString('base64'),
    ownerEnvelope: envelope,
    submitterEnvelope: envelope,
  };
  await participant
    .put(`/rooms/${room.id}/submissions/${created.body.id}/metadata`, metadata)
    .expect(204);
  await participant
    .put(`/rooms/${room.id}/submissions/${created.body.id}/metadata`, metadata)
    .expect(204);
  const chunk = Buffer.alloc(16, 9);
  await participant
    .put(
      `/rooms/${room.id}/submissions/${created.body.id}/chunks/0`,
      chunk,
      'application/octet-stream',
    )
    .expect(201);
  await participant
    .put(
      `/rooms/${room.id}/submissions/${created.body.id}/chunks/0`,
      chunk,
      'application/octet-stream',
    )
    .expect(200);
  await participant
    .put(
      `/rooms/${room.id}/submissions/${created.body.id}/chunks/0`,
      Buffer.alloc(16, 1),
      'application/octet-stream',
    )
    .expect(409);
  const digest = sha256(chunk);
  const manifest = sha256(Buffer.concat([descriptor, digest])).toString('hex');
  const completed = await participant
    .post(`/rooms/${room.id}/submissions/${created.body.id}/complete`, {
      chunkCount: 1,
      manifestSha256: manifest,
    })
    .expect(200);
  const recovered = await participant
    .post(`/rooms/${room.id}/submissions`, { uploadId })
    .expect(201);
  assert.equal(recovered.body.complete, true);
  assert.deepEqual(recovered.body.receipt, completed.body.receipt);
  const listing = await participant
    .get(`/rooms/${room.id}/submissions`)
    .expect(200);
  assert.equal(listing.body.submissions.length, 1);
  assert.equal(
    (await owner.get(`/rooms/${room.id}/submissions`).expect(200)).body
      .submissions.length,
    1,
  );
  await outsider
    .get(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`)
    .expect(403);
  const downloaded = await participant
    .get(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`)
    .expect(200);
  assert.deepEqual(downloaded.body, chunk);
  await owner.post(`/rooms/${room.id}/close`).expect(200);
  await owner.get(`/rooms/${room.id}/submissions`).expect(410);
});

test('submission start and chunk writes require origin, CSRF and current approved membership', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await makeRoom(owner);
  await participant
    .post(`/join/${room.joinCode}`, { label: 'Participant' })
    .expect(200);
  const member = (await owner.get(`/rooms/${room.id}/members`).expect(200))
    .body[0];
  await owner
    .patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' })
    .expect(200);
  await owner
    .post(`/rooms/${room.id}/submissions/owner-key`, {
      publicKey: base64(await createPublicKey()),
    })
    .expect(201);
  await participant
    .post(`/rooms/${room.id}/submissions/submitter-key`, {
      publicKey: base64(await createPublicKey()),
    })
    .expect(201);
  const start = await participant
    .post(`/rooms/${room.id}/submissions`, { uploadId: randomUUID() })
    .expect(201);
  await owner
    .patch(`/rooms/${room.id}/members/${member.id}`, { status: 'revoked' })
    .expect(200);
  await participant
    .put(
      `/rooms/${room.id}/submissions/${start.body.id}/chunks/0`,
      Buffer.alloc(16),
      'application/octet-stream',
    )
    .expect(403);
  await participant
    .post(`/rooms/${room.id}/submissions`, { uploadId: randomUUID() })
    .expect(403);
});

type Browser = Awaited<ReturnType<typeof browser>>;
const metadata = () => ({
  descriptor: Buffer.alloc(69, 7).toString('base64'),
  ownerEnvelope: {
    enc: Buffer.alloc(65, 4).toString('base64'),
    ciphertext: Buffer.alloc(48, 8).toString('base64'),
  },
  submitterEnvelope: {
    enc: Buffer.alloc(65, 4).toString('base64'),
    ciphertext: Buffer.alloc(48, 9).toString('base64'),
  },
});

async function admit(
  owner: Browser,
  participant: Browser,
  room: Room,
  label: string,
) {
  const membership = (
    await participant.post(`/join/${room.joinCode}`, { label }).expect(200)
  ).body;
  await owner
    .patch(`/rooms/${room.id}/members/${membership.id}`, { status: 'approved' })
    .expect(200);
  await participant
    .post(`/rooms/${room.id}/submissions/submitter-key`, {
      publicKey: base64(await createPublicKey()),
    })
    .expect(201);
  return membership.id as string;
}

async function inbox() {
  const owner = await browser();
  const participant = await browser();
  const room = await makeRoom(owner);
  await owner
    .post(`/rooms/${room.id}/submissions/owner-key`, {
      publicKey: base64(await createPublicKey()),
    })
    .expect(201);
  const memberId = await admit(owner, participant, room, 'Original submitter');
  return {
    owner,
    participant,
    room,
    memberId,
    path: `/rooms/${room.id}/submissions`,
  };
}

async function beginUpload(participant: Browser, path: string) {
  const id = randomUUID();
  await participant.post(path, { uploadId: id }).expect(201);
  const data = metadata();
  await participant.put(`${path}/${id}/metadata`, data).expect(204);
  return { id, data, objectPath: `${path}/${id}` };
}

function manifest(descriptor: string, chunks: Buffer[]) {
  return sha256(
    Buffer.concat([Buffer.from(descriptor, 'base64'), ...chunks.map(sha256)]),
  ).toString('hex');
}

async function seedCompleted(room: Room, count: number, encryptedBytes = 16) {
  const [owner] = await database.query<{ owner_id: string }>(
    'SELECT owner_id FROM rooms WHERE id = $1',
    [room.id],
  );
  const [member] = await database.query<{ session_id: string }>(
    'SELECT session_id FROM memberships WHERE room_id = $1 LIMIT 1',
    [room.id],
  );
  const ids = Array.from({ length: count }, () => randomUUID());
  await database.query(
    `INSERT INTO private_submissions
    (id, room_id, submitter_id, encrypted_descriptor, chunk_count, encrypted_bytes, status, manifest_sha256, receipt, completed_at, created_at)
    SELECT u.id, $2, $3, $4, 1, $5, 'complete', $6, '{}'::jsonb, clock_timestamp(),
      '2026-10-14T00:00:00.123000Z'::timestamptz + u.position * interval '1 microsecond'
    FROM unnest($1::uuid[]) WITH ORDINALITY AS u(id, position)`,
    [
      ids,
      room.id,
      member.session_id,
      Buffer.alloc(69),
      encryptedBytes,
      '0'.repeat(64),
    ],
  );
  await database.query(
    `INSERT INTO submission_envelopes (submission_id, recipient_id, enc, ciphertext)
    SELECT id, $2, $3, $4 FROM unnest($1::uuid[]) AS id`,
    [ids, owner.owner_id, Buffer.alloc(65), Buffer.alloc(48)],
  );
  return ids;
}

test('approved peers and cross-room requests cannot read or change another submission', async () => {
  const { owner, participant, room, path } = await inbox();
  const peer = await browser();
  await admit(owner, peer, room, 'Another approved participant');
  const upload = await beginUpload(participant, path);
  await peer.put(`${upload.objectPath}/metadata`, upload.data).expect(404);
  await peer
    .put(
      `${upload.objectPath}/chunks/0`,
      Buffer.alloc(16),
      'application/octet-stream',
    )
    .expect(404);
  await peer.delete(upload.objectPath).expect(404);
  await peer
    .post(`${upload.objectPath}/complete`, {
      chunkCount: 1,
      manifestSha256: '0'.repeat(64),
    })
    .expect(404);
  const chunk = Buffer.alloc(16, 12);
  await participant
    .put(`${upload.objectPath}/chunks/0`, chunk, 'application/octet-stream')
    .expect(201);
  await participant
    .post(`${upload.objectPath}/complete`, {
      chunkCount: 1,
      manifestSha256: manifest(upload.data.descriptor, [chunk]),
    })
    .expect(200);
  assert.deepEqual((await peer.get(path).expect(200)).body.submissions, []);
  await peer.get(`${upload.objectPath}/chunks/0`).expect(404);
  const otherRoom = await makeRoom(owner);
  await admit(owner, participant, otherRoom, 'Same browser, another room');
  const foreignPath = `/rooms/${otherRoom.id}/submissions/${upload.id}`;
  await participant.get(`${foreignPath}/chunks/0`).expect(404);
  await participant.put(`${foreignPath}/metadata`, upload.data).expect(404);
  await participant
    .post(`/rooms/${otherRoom.id}/submissions`, { uploadId: upload.id })
    .expect(409);
});

test('binary writes reject missing CSRF, foreign origins and unauthorized bodies before parsing', async () => {
  const { participant, path } = await inbox();
  const upload = await beginUpload(participant, path);
  await participant.agent
    .put(`/api${upload.objectPath}/chunks/0`)
    .set('Origin', origin)
    .set('Content-Type', 'application/octet-stream')
    .send(Buffer.alloc(16))
    .expect(403);
  await participant.agent
    .put(`/api${upload.objectPath}/chunks/0`)
    .set('Origin', 'https://foreign.example')
    .set('Content-Type', 'application/octet-stream')
    .send(Buffer.alloc(16))
    .expect(403);
  const outsider = await browser();
  await outsider.agent
    .put(`/api${upload.objectPath}/chunks/0`)
    .set('Origin', origin)
    .set('X-CSRF-Token', outsider.csrf)
    .set('Content-Type', 'application/octet-stream')
    .set('Content-Length', '1048593')
    .send(Buffer.alloc(16))
    .expect(403);
  await participant
    .put(
      `${upload.objectPath}/chunks/0`,
      Buffer.alloc(1048593),
      'application/octet-stream',
    )
    .expect(413);
});

test('metadata retries, chunk completeness, corruption and duplicate completion are enforced', async () => {
  const { participant, path } = await inbox();
  const upload = await beginUpload(participant, path);
  await participant
    .put(`${upload.objectPath}/metadata`, upload.data)
    .expect(204);
  await participant
    .put(`${upload.objectPath}/metadata`, {
      ...upload.data,
      descriptor: Buffer.alloc(69, 11).toString('base64'),
    })
    .expect(409);
  await participant
    .put(
      `${upload.objectPath}/chunks/1`,
      Buffer.alloc(16),
      'application/octet-stream',
    )
    .expect(409);
  const chunk = Buffer.alloc(16, 13);
  await participant
    .put(`${upload.objectPath}/chunks/0`, chunk, 'application/octet-stream')
    .expect(201);
  const completion = {
    chunkCount: 1,
    manifestSha256: manifest(upload.data.descriptor, [chunk]),
  };
  await participant
    .post(`${upload.objectPath}/complete`, { ...completion, chunkCount: 2 })
    .expect(409);
  await participant
    .post(`${upload.objectPath}/complete`, {
      ...completion,
      manifestSha256: '0'.repeat(64),
    })
    .expect(422);
  await database.query(
    'UPDATE submission_chunks SET ciphertext = $2 WHERE submission_id = $1',
    [upload.id, Buffer.alloc(16, 1)],
  );
  await participant
    .post(`${upload.objectPath}/complete`, completion)
    .expect(409);
  await database.query(
    'UPDATE submission_chunks SET ciphertext = $2 WHERE submission_id = $1',
    [upload.id, chunk],
  );
  const accepted = await Promise.all([
    participant.post(`${upload.objectPath}/complete`, completion),
    participant.post(`${upload.objectPath}/complete`, completion),
  ]);
  assert.deepEqual(
    accepted.map((result) => result.status),
    [200, 200],
  );
  assert.deepEqual(accepted[0].body.receipt, accepted[1].body.receipt);
  await participant
    .post(`${upload.objectPath}/complete`, {
      ...completion,
      manifestSha256: '1'.repeat(64),
    })
    .expect(409);
  assert.deepEqual(
    (await participant.post(path, { uploadId: upload.id }).expect(201)).body
      .receipt,
    accepted[0].body.receipt,
  );
});

test('closure, expiry and revocation block in-progress writes and completed downloads', async () => {
  for (const terminal of ['closed', 'expired', 'revoked'] as const) {
    const { owner, participant, room, memberId, path } = await inbox();
    const pending = await beginUpload(participant, path);
    const completed = await beginUpload(participant, path);
    const chunk = Buffer.alloc(16);
    await participant
      .put(
        `${completed.objectPath}/chunks/0`,
        chunk,
        'application/octet-stream',
      )
      .expect(201);
    await participant
      .post(`${completed.objectPath}/complete`, {
        chunkCount: 1,
        manifestSha256: manifest(completed.data.descriptor, [chunk]),
      })
      .expect(200);
    if (terminal === 'closed')
      await owner.post(`/rooms/${room.id}/close`).expect(200);
    if (terminal === 'expired')
      await database.query(
        "UPDATE rooms SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() - interval '1 second' WHERE id = $1",
        [room.id],
      );
    if (terminal === 'revoked')
      await owner
        .patch(`/rooms/${room.id}/members/${memberId}`, { status: 'revoked' })
        .expect(200);
    const status = terminal === 'revoked' ? 403 : 410;
    await participant.get(`${path}/keys`).expect(status);
    await participant.get(path).expect(status);
    await participant.get(`${completed.objectPath}/chunks/0`).expect(status);
    await participant.post(path, { uploadId: randomUUID() }).expect(status);
    await participant
      .put(`${pending.objectPath}/metadata`, pending.data)
      .expect(status);
    await participant
      .put(`${pending.objectPath}/chunks/0`, chunk, 'application/octet-stream')
      .expect(status);
    await participant
      .post(`${pending.objectPath}/complete`, {
        chunkCount: 1,
        manifestSha256: '0'.repeat(64),
      })
      .expect(status);
    await participant.delete(pending.objectPath).expect(status);
  }
});

test('submission pagination keeps full PostgreSQL timestamp precision and rejects malformed cursors', async () => {
  const { owner, room, path } = await inbox();
  const ids = await seedCompleted(room, 51);
  const first = (await owner.get(path).expect(200)).body;
  assert.equal(first.submissions.length, 50);
  const decoded = JSON.parse(
    Buffer.from(first.nextCursor, 'base64url').toString('utf8'),
  );
  assert.match(decoded.createdAt, /\.\d{6}Z$/);
  const second = (
    await owner.get(`${path}?before=${first.nextCursor}`).expect(200)
  ).body;
  assert.equal(second.submissions.length, 1);
  assert.equal(second.nextCursor, null);
  assert.equal(
    new Set(
      [...first.submissions, ...second.submissions].map(
        (item: { id: string }) => item.id,
      ),
    ).size,
    ids.length,
  );
  await owner.get(`${path}?before=not-a-cursor`).expect(422);
});

test('pending and total object limits are bounded and stale uploads free capacity', async () => {
  const { participant, room, path } = await inbox();
  const ids: string[] = [];
  for (let index = 0; index < 10; index += 1) {
    ids.push(
      (await participant.post(path, { uploadId: randomUUID() }).expect(201))
        .body.id,
    );
  }
  await participant.post(path, { uploadId: randomUUID() }).expect(429);
  await participant.delete(`${path}/${ids[0]}`).expect(204);
  await participant.post(path, { uploadId: randomUUID() }).expect(201);
  await database.query(
    "UPDATE private_submissions SET created_at = clock_timestamp() - interval '25 hours' WHERE room_id = $1",
    [room.id],
  );
  const fresh = await participant
    .post(path, { uploadId: randomUUID() })
    .expect(201);
  const [pending] = await database.query<{ count: number }>(
    'SELECT count(*)::int AS count FROM private_submissions WHERE room_id = $1',
    [room.id],
  );
  assert.equal(pending.count, 1);
  await participant.delete(`${path}/${fresh.body.id}`).expect(204);
  await seedCompleted(room, 1000);
  await participant.post(path, { uploadId: randomUUID() }).expect(413);
});

test('concurrent chunk writes allocate room quota atomically', async () => {
  const { participant, room, path } = await inbox();
  const ids = await seedCompleted(room, 21, 0);
  const quota = 5 * 1024 ** 3;
  for (let index = 0; index < ids.length; index += 1) {
    await database.query(
      'UPDATE private_submissions SET encrypted_bytes = $2 WHERE id = $1',
      [
        ids[index],
        Math.min(262144000, Math.max(0, quota - 16 - index * 262144000)),
      ],
    );
  }
  const one = await beginUpload(participant, path);
  const two = await beginUpload(participant, path);
  const writes = await Promise.all(
    [one, two].map((upload) =>
      participant.put(
        `${upload.objectPath}/chunks/0`,
        Buffer.alloc(16),
        'application/octet-stream',
      ),
    ),
  );
  assert.deepEqual(writes.map((result) => result.status).sort(), [201, 413]);
  const [usage] = await database.query<{ total: string }>(
    'SELECT SUM(encrypted_bytes)::text AS total FROM private_submissions WHERE room_id = $1',
    [room.id],
  );
  assert.equal(Number(usage.total), quota);
});

test(
  'the API accepts a 250 MiB payload with all GCM tags and rejects another chunk',
  // The full 250 MiB path takes about 232 seconds on the constrained 8 GiB
  // verification host. Keep the complete-size assertion while allowing for
  // hardware and CI load variation.
  { timeout: 600_000 },
  async () => {
    const { participant, room, path } = await inbox();
    const upload = await beginUpload(participant, path);
    const chunk = Buffer.alloc(1024 * 1024 + 16, 21);
    const hash = sha256(chunk);
    const manifestHash = createHash('sha256').update(
      Buffer.from(upload.data.descriptor, 'base64'),
    );
    for (let index = 0; index < 250; index += 1) {
      await participant
        .put(
          `${upload.objectPath}/chunks/${index}`,
          chunk,
          'application/octet-stream',
        )
        .expect(201);
      manifestHash.update(hash);
    }
    await participant
      .put(
        `${upload.objectPath}/chunks/250`,
        Buffer.alloc(16),
        'application/octet-stream',
      )
      .expect(422);
    const accepted = await participant
      .post(`${upload.objectPath}/complete`, {
        chunkCount: 250,
        manifestSha256: manifestHash.digest('hex'),
      })
      .expect(200);
    assert.equal(
      accepted.body.receipt.encryptedBytes,
      250 * (1024 * 1024 + 16),
    );
    await database.query('DELETE FROM rooms WHERE id = $1', [room.id]);
  },
);
