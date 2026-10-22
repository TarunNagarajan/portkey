import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import supertest from 'supertest';
import type { Express } from 'express';
import { Group } from '@semaphore-protocol/group';
import { Identity } from '@semaphore-protocol/identity';
import { generateProof } from '@semaphore-protocol/proof';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import type { Room } from '../shared/rooms.js';
import { WORKSHOP_PROOF_DEPTH, workshopScope } from '../shared/workshopProof.js';

const origin = 'http://localhost:5173';
let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
});
after(async () => {
  const curve = (globalThis as typeof globalThis & { curve_bn128?: { terminate: () => Promise<void> } }).curve_bn128;
  if (curve) await curve.terminate();
  await database.close();
});

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = response.body.csrfToken as string;
  const cookies = response.headers['set-cookie'];
  const cookie = Array.isArray(cookies) ? cookies[0] : cookies;
  const sessionToken = cookie.split(';')[0].split('=')[1];
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions WHERE token_hash = $1', [createHash('sha256').update(sessionToken).digest('hex')],
  );
  return {
    agent,
    sessionId: session.id,
    csrf,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) => agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
  };
}

test('workshop enrollment saves only commitments and a genuine depth-10 Semaphore proof admits once', async () => {
  const owner = await browser();
  const attendee = await browser();
  const room = (await owner.post('/rooms', {
    title: 'Proof workshop', description: 'Materials',
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(), admissionPolicy: 'proof',
  }).expect(201)).body as Room;
  await owner.post(`/rooms/${room.id}/open`).expect(200);
  const issued = await owner.post(`/rooms/${room.id}/enrollments`, { count: 3 }).expect(201);
  const invite = issued.body.enrollments[0] as { id: string; token: string };
  const growthInvite = issued.body.enrollments[1] as { id: string; token: string };
  const revokedInvite = issued.body.enrollments[2] as { id: string; token: string };
  await owner.patch(`/rooms/${room.id}/enrollments/${revokedInvite.id}`, { status: 'revoked' }).expect(200);
  await attendee.post(`/join/${room.joinCode}/enroll`, { token: revokedInvite.token, commitment: '1' }).expect(403);
  const identity = new Identity();
  for (const commitment of ['not-a-number', '0x12', '-1', '01', '0', '9'.repeat(78)]) {
    await attendee.post(`/join/${room.joinCode}/enroll`, { token: invite.token, commitment }).expect(422);
  }
  await attendee.post(`/join/${room.joinCode}/enroll`, { token: invite.token, commitment: identity.commitment.toString() })
    .expect(200).expect(({ body }) => assert.equal(body.enrolled, true));
  await attendee.post(`/join/${room.joinCode}/enroll`, { token: invite.token, commitment: identity.commitment.toString() })
    .expect(200).expect(({ body }) => assert.equal(body.alreadyEnrolled, true));
  await attendee.post(`/join/${room.joinCode}/enroll`, { token: invite.token, commitment: new Identity().commitment.toString() }).expect(403);
  await attendee.post(`/join/${room.joinCode}`, { label: 'Manual bypass' }).expect(409);
  await owner.get(`/rooms/${room.id}/enrollments`).expect(200).expect(({ body }) => {
    assert.equal(body.counts.enrolled, 1);
    assert.equal(JSON.stringify(body).includes(invite.token), false);
    assert.equal(JSON.stringify(body).includes(identity.commitment.toString()), false);
  });
  const [stored] = await database.query<{ token_digest: Buffer; enrolled_commitment: string }>(
    'SELECT token_digest, enrolled_commitment FROM room_proof_invites WHERE id = $1', [invite.id],
  );
  assert.equal(Buffer.from(stored.token_digest).toString('hex'), createHash('sha256').update(Buffer.from(invite.token, 'base64url')).digest('hex'));
  assert.equal(stored.enrolled_commitment, identity.commitment.toString());
  await attendee.get(`/rooms/${room.id}`).expect(403);
  const [notAdmitted] = await database.query<{ count: number }>(
    'SELECT count(*)::int AS count FROM memberships WHERE room_id = $1', [room.id],
  );
  assert.equal(notAdmitted.count, 0);

  let challenge = (await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as {
    challengeId: string; depth: number; root: string; scope: string; message: string; commitments: string[];
  };
  const staleChallenge = challenge;
  challenge = (await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as typeof challenge;
  assert.equal(challenge.challengeId, staleChallenge.challengeId);
  assert.notEqual(challenge.message, staleChallenge.message);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: staleChallenge.challengeId,
    proof: {
      merkleTreeDepth: staleChallenge.depth, merkleTreeRoot: staleChallenge.root,
      message: staleChallenge.message, nullifier: '1', scope: staleChallenge.scope,
      points: Array(8).fill('1'),
    },
  }).expect(403);
  assert.equal(challenge.depth, WORKSHOP_PROOF_DEPTH);
  assert.equal(challenge.commitments.length, 1);
  const growthIdentity = new Identity();
  await attendee.post(`/join/${room.joinCode}/enroll`, { token: growthInvite.token, commitment: growthIdentity.commitment.toString() }).expect(200);
  const group = new Group(challenge.commitments.map(BigInt));
  assert.equal(group.root.toString(), challenge.root);
  const proof = await generateProof(identity, group, challenge.message, challenge.scope, challenge.depth, {
    wasm: resolve('public/zk/semaphore-10.wasm'),
    zkey: resolve('public/zk/semaphore-10.zkey'),
  });

  const otherRoom = (await owner.post('/rooms', {
    title: 'Another proof room', description: '', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), admissionPolicy: 'proof',
  }).expect(201)).body as Room;
  await owner.post(`/rooms/${otherRoom.id}/open`).expect(200);
  await attendee.post(`/join/${otherRoom.joinCode}/prove`, { challengeId: challenge.challengeId, proof }).expect(403);

  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: challenge.challengeId,
    proof: { ...proof, message: (BigInt(proof.message) + 1n).toString() },
  }).expect(403);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: challenge.challengeId,
    proof: { ...proof, merkleTreeRoot: (BigInt(proof.merkleTreeRoot) + 1n).toString() },
  }).expect(403);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: challenge.challengeId,
    proof: { ...proof, scope: (BigInt(proof.scope) + 1n).toString() },
  }).expect(403);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: challenge.challengeId,
    proof: { ...proof, scope: '0x12' },
  }).expect(422);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: challenge.challengeId,
    proof: { ...proof, merkleTreeDepth: 9 },
  }).expect(422);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    challengeId: challenge.challengeId,
    proof: { ...proof, points: proof.points.map(() => '0') as unknown as typeof proof.points },
  }).expect(403);
  for (const value of ['not-a-number', '0x12', '-1', '01', '9'.repeat(78)]) {
    await attendee.post(`/join/${room.joinCode}/prove`, {
      challengeId: challenge.challengeId,
      proof: { ...proof, message: value },
    }).expect(422);
  }
  const admitted = await attendee.post(`/join/${room.joinCode}/prove`, { challengeId: challenge.challengeId, proof }).expect(200);
  assert.equal(admitted.body.status, 'approved');
  await attendee.post(`/join/${room.joinCode}/prove`, { challengeId: challenge.challengeId, proof }).expect(200);
  const replayBrowser = await browser();
  const replayChallenge = (await replayBrowser.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as typeof challenge;
  const replayGroup = new Group(replayChallenge.commitments.map(BigInt));
  const replayProof = await generateProof(identity, replayGroup, replayChallenge.message, replayChallenge.scope, replayChallenge.depth, {
    wasm: resolve('public/zk/semaphore-10.wasm'),
    zkey: resolve('public/zk/semaphore-10.zkey'),
  });
  await replayBrowser.post(`/join/${room.joinCode}/prove`, { challengeId: replayChallenge.challengeId, proof: replayProof }).expect(403);
  const [unusedReplay] = await database.query<{ consumed_at: Date | null }>(
    'SELECT consumed_at FROM room_proof_challenges WHERE id = $1', [replayChallenge.challengeId],
  );
  assert.equal(unusedReplay.consumed_at, null);
  const expiredBrowser = await browser();
  const expiredChallenge = (await expiredBrowser.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as typeof challenge;
  await database.query('UPDATE room_proof_challenges SET expires_at = clock_timestamp() - interval \'1 second\' WHERE id = $1', [expiredChallenge.challengeId]);
  await expiredBrowser.post(`/join/${room.joinCode}/prove`, { challengeId: expiredChallenge.challengeId, proof }).expect(403);
  await replayBrowser.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200);
  const [expiredCleanup] = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM room_proof_challenges WHERE id = $1', [expiredChallenge.challengeId]);
  assert.equal(expiredCleanup.count, 0);
  const [membership] = await database.query<{ id: string }>(
    'SELECT id FROM memberships WHERE room_id = $1 AND status = $2', [room.id, 'approved'],
  );
  await owner.patch(`/rooms/${room.id}/members/${membership.id}`, { status: 'revoked' }).expect(200);
  await attendee.post(`/join/${room.joinCode}/prove`, { challengeId: challenge.challengeId, proof }).expect(403)
    .expect(({ body }) => assert.equal(body.error.code, 'ADMISSION_DENIED'));
  await attendee.get(`/rooms/${room.id}`).expect(403);
  await database.query('DELETE FROM memberships WHERE room_id = $1 AND session_id = $2', [room.id, attendee.sessionId]);
  await database.query('DELETE FROM sessions WHERE id = $1', [attendee.sessionId]);
  const [permanent] = await database.query<{ session_id: string | null }>(
    'SELECT session_id FROM room_proof_nullifiers WHERE room_id = $1 AND nullifier = $2', [room.id, proof.nullifier],
  );
  assert.equal(permanent.session_id, null);
  await replayBrowser.post(`/join/${room.joinCode}/prove`, { challengeId: replayChallenge.challengeId, proof: replayProof }).expect(403);
  const [records] = await database.query<{ nullifiers: number; activity: number }>(
    `SELECT (SELECT count(*)::int FROM room_proof_nullifiers WHERE room_id = $1) AS nullifiers,
       (SELECT count(*)::int FROM room_activity WHERE room_id = $1 AND kind = 'proof_admitted') AS activity`, [room.id],
  );
  assert.deepEqual(records, { nullifiers: 1, activity: 1 });
});

test('geofence and activity failures leave the proof challenge and nullifier available', async (context) => {
  context.mock.method(console, 'error', () => {});
  const owner = await browser();
  const attendee = await browser();
  const room = (await owner.post('/rooms', {
    title: 'Geofenced proof workshop', description: 'Materials',
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(), admissionPolicy: 'proof',
  }).expect(201)).body as Room;
  await owner.post(`/rooms/${room.id}/geo`, { lat: 17.385, lng: 78.487, radiusM: 500, label: 'Workshop' }).expect(200);
  await owner.post(`/rooms/${room.id}/open`).expect(200);
  const { token } = (await owner.post(`/rooms/${room.id}/enrollments`, { count: 1 }).expect(201)).body.enrollments[0] as { token: string };
  const identity = new Identity();
  await attendee.post(`/join/${room.joinCode}/enroll`, { token, commitment: identity.commitment.toString() }).expect(200);
  const challenge = (await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as {
    challengeId: string; depth: number; root: string; scope: string; message: string; commitments: string[];
  };
  const group = new Group(challenge.commitments.map(BigInt));
  const proof = await generateProof(identity, group, challenge.message, challenge.scope, challenge.depth, {
    wasm: resolve('public/zk/semaphore-10.wasm'),
    zkey: resolve('public/zk/semaphore-10.zkey'),
  });
  const body = { challengeId: challenge.challengeId, proof };
  await attendee.post(`/join/${room.joinCode}/prove`, {
    ...body, lat: 0, lng: 0, accuracyM: 10, timestamp: new Date().toISOString(),
  }).expect(403).expect(({ body: result }) => assert.equal(result.error.code, 'GEO_OUTSIDE'));
  await database.exec("ALTER TABLE room_activity ADD CONSTRAINT test_proof_activity_failure CHECK (kind <> 'proof_admitted') NOT VALID");
  try {
    await attendee.post(`/join/${room.joinCode}/prove`, {
      ...body, lat: 17.385, lng: 78.487, accuracyM: 10, timestamp: new Date().toISOString(),
    }).expect(500);
    const [rollback] = await database.query<{ nullifiers: number; memberships: number; consumed_at: Date | null }>(
      `SELECT (SELECT count(*)::int FROM room_proof_nullifiers WHERE room_id = $1) AS nullifiers,
        (SELECT count(*)::int FROM memberships WHERE room_id = $1) AS memberships,
        (SELECT consumed_at FROM room_proof_challenges WHERE id = $2) AS consumed_at`, [room.id, challenge.challengeId],
    );
    assert.equal(rollback.nullifiers, 0);
    assert.equal(rollback.memberships, 0);
    assert.equal(rollback.consumed_at, null);
  } finally {
    await database.exec('ALTER TABLE room_activity DROP CONSTRAINT test_proof_activity_failure');
  }
  await attendee.post(`/join/${room.joinCode}/prove`, {
    ...body, lat: 17.385, lng: 78.487, accuracyM: 10, timestamp: new Date().toISOString(),
  }).expect(200);
  await attendee.post(`/join/${room.joinCode}/prove`, {
    ...body, lat: 0, lng: 0, accuracyM: 10, timestamp: new Date().toISOString(),
  }).expect(403).expect(({ body: result }) => assert.equal(result.error.code, 'GEO_OUTSIDE'));
  const [consumed] = await database.query<{ nullifiers: number }>(
    'SELECT count(*)::int AS nullifiers FROM room_proof_nullifiers WHERE room_id = $1', [room.id],
  );
  assert.equal(consumed.nullifiers, 1);
});

test('migration 008 upgrades legacy rooms and proof policy remains draft-only with clean templates', async () => {
  const legacy = await openDatabase();
  try {
    await legacy.exec('CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())');
    const directory = fileURLToPath(new URL('../server/migrations/', import.meta.url));
    for (const name of ['001_initial.sql', '002_room_activity.sql', '003_private_submissions.sql', '004_submission_limits.sql', '005_submission_retention.sql', '006_geofence.sql', '007_admission_passes.sql']) {
      const sql = (await readFile(join(directory, name), 'utf8')).replace(/\r\n/g, '\n');
      await legacy.exec(sql);
      await legacy.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [name, createHash('sha256').update(sql).digest('hex')]);
    }
    const ownerId = randomUUID();
    const participantId = randomUUID();
    const approvalRoomId = randomUUID();
    const passRoomId = randomUUID();
    const now = new Date();
    const expiry = new Date(Date.now() + 3_600_000);
    await legacy.query('INSERT INTO sessions (id, token_hash, expires_at) VALUES ($1, $2, $3), ($4, $5, $6)', [ownerId, 'a'.repeat(64), expiry, participantId, 'b'.repeat(64), expiry]);
    await legacy.query(
      `INSERT INTO rooms (id, owner_id, join_code, title, description, status, expires_at, admission_policy)
       VALUES ($1, $2, $3, 'Legacy approval', '', 'open', $4, 'approval'),
              ($5, $2, $6, 'Legacy pass', '', 'open', $4, 'pass')`,
      [approvalRoomId, ownerId, randomUUID().slice(0, 16), expiry, passRoomId, randomUUID().slice(0, 16)],
    );
    await legacy.query(
      `INSERT INTO memberships (id, room_id, session_id, label, status, requested_at, decided_at)
       VALUES ($1, $2, $3, 'Legacy attendee', 'approved', $4, $4)`, [randomUUID(), approvalRoomId, participantId, now],
    );
    await legacy.query(
      `INSERT INTO room_admission_passes (id, room_id, pass_number, token_digest, redeemed_at, redeemer_session_id)
       VALUES ($1, $2, 1, decode($3, 'hex'), $4, $5)`,
      [randomUUID(), passRoomId, 'c'.repeat(64), now, participantId],
    );
    await migrate(legacy);
    const [latest] = await legacy.query<{ count: number }>("SELECT count(*)::int AS count FROM schema_migrations WHERE name = '008_workshop_proof_admission.sql'");
    assert.equal(latest.count, 1);
    const [policy] = await legacy.query<{ admission_policy: string }>("SELECT column_default AS admission_policy FROM information_schema.columns WHERE table_name = 'rooms' AND column_name = 'admission_policy'");
    assert.match(policy.admission_policy, /approval/);
    const [legacyRooms] = await legacy.query<{ approval: number; pass: number; membership: number; redeemed: number }>(
      `SELECT (SELECT count(*)::int FROM rooms WHERE id = $1 AND admission_policy = 'approval') AS approval,
        (SELECT count(*)::int FROM rooms WHERE id = $2 AND admission_policy = 'pass') AS pass,
        (SELECT count(*)::int FROM memberships WHERE room_id = $1 AND status = 'approved') AS membership,
        (SELECT count(*)::int FROM room_admission_passes WHERE room_id = $2 AND redeemed_at IS NOT NULL AND redeemer_session_id = $3) AS redeemed`,
      [approvalRoomId, passRoomId, participantId],
    );
    assert.deepEqual(legacyRooms, { approval: 1, pass: 1, membership: 1, redeemed: 1 });
  } finally { await legacy.close(); }

  const owner = await browser();
  const attendee = await browser();
  const otherOwner = await browser();
  const legacyRoom = (await owner.post('/rooms', {
    title: 'Default approval', description: 'Materials', expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }).expect(201)).body as Room;
  assert.equal(legacyRoom.admissionPolicy, 'approval');
  const room = (await owner.post('/rooms', {
    title: 'Proof template', description: 'Materials', expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    admissionPolicy: 'proof',
  }).expect(201)).body as Room;
  await owner.patch(`/rooms/${room.id}`, {
    title: room.title, description: room.description, expiresAt: room.expiresAt,
  }).expect(200).expect(({ body }) => assert.equal(body.admissionPolicy, 'proof'));
  await owner.post(`/rooms/${room.id}/enrollments`, { count: 21 }).expect(422);
  await owner.post(`/rooms/${room.id}/enrollments`, { count: 1, extra: true }).expect(422);
  await otherOwner.get(`/rooms/${room.id}/enrollments`).expect(403);
  await owner.agent.post(`/api/rooms/${room.id}/enrollments`).send({ count: 1 }).expect(403);
  await owner.agent.post(`/api/rooms/${room.id}/enrollments`).set('Origin', 'https://attacker.example').set('X-CSRF-Token', owner.csrf).send({ count: 1 }).expect(403);
  await attendee.post(`/join/${room.joinCode}/proof-challenge`, { extra: true }).expect(422);
  await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(409);
  await owner.post(`/rooms/${room.id}/open`).expect(200);
  await owner.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(409).expect(({ body }) => assert.equal(body.error.code, 'ALREADY_OWNER'));
  await owner.patch(`/rooms/${room.id}`, {
    title: room.title, description: room.description, expiresAt: room.expiresAt, admissionPolicy: 'approval',
  }).expect(409).expect(({ body }) => assert.equal(body.error.code, 'POLICY_LOCKED'));
  const { token } = (await owner.post(`/rooms/${room.id}/enrollments`, { count: 1 }).expect(201)).body.enrollments[0] as { token: string };
  const templateIdentity = new Identity();
  await attendee.post(`/join/${room.joinCode}/enroll`, { token, commitment: templateIdentity.commitment.toString() }).expect(200);
  const sourceChallenge = (await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as { challengeId: string };
  const template = (await owner.post(`/rooms/${room.id}/duplicate`, { expiresAt: new Date(Date.now() + 3_600_000).toISOString() }).expect(201)).body as Room;
  assert.equal(template.admissionPolicy, 'proof');
  assert.notEqual(workshopScope(template.id), workshopScope(room.id));
  await owner.get(`/rooms/${template.id}/enrollments`).expect(200).expect(({ body }) => {
    assert.deepEqual(body.counts, { enrolled: 0, available: 0, revoked: 0 });
  });
  const [templateState] = await database.query<{ commitments: number; invites: number; challenges: number; nullifiers: number }>(
    `SELECT (SELECT count(*)::int FROM room_proof_commitments WHERE room_id = $1) AS commitments,
       (SELECT count(*)::int FROM room_proof_invites WHERE room_id = $1) AS invites,
       (SELECT count(*)::int FROM room_proof_challenges WHERE room_id = $1) AS challenges,
       (SELECT count(*)::int FROM room_proof_nullifiers WHERE room_id = $1) AS nullifiers`, [template.id],
  );
  assert.deepEqual(templateState, { commitments: 0, invites: 0, challenges: 0, nullifiers: 0 });
  const [sourceState] = await database.query<{ commitments: number; challenges: number }>(
    `SELECT (SELECT count(*)::int FROM room_proof_commitments WHERE room_id = $1) AS commitments,
       (SELECT count(*)::int FROM room_proof_challenges WHERE room_id = $1 AND id = $2) AS challenges`,
    [room.id, sourceChallenge.challengeId],
  );
  assert.deepEqual(sourceState, { commitments: 1, challenges: 1 });
  await attendee.post(`/join/${room.joinCode}`, { label: 'Manual bypass' }).expect(409).expect(({ body }) => assert.equal(body.error.code, 'PROOF_REQUIRED'));
  await owner.post(`/rooms/${room.id}/close`).expect(200);
  await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(410);
});
