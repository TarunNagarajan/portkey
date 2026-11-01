import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import supertest from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from './database.js';
import { migrate } from '../server/migrations.js';
import { issuerPublicKey } from '../server/zk.js';
import type { Member, PublicRoom, Room } from '../shared/rooms.js';
import type { ActivityPage } from '../shared/activity.js';
import {
  credentialNullifier,
  roomScope,
  type CredentialFile,
  type CredentialProofPayload,
} from '../shared/credentials.js';
import {
  generateIssuer,
  issueCredential,
  type IssuerKeyFile,
} from '../scripts/issuerLib.js';

const origin = 'http://localhost:5173';
const root = fileURLToPath(new URL('..', import.meta.url));
const devIssuer = JSON.parse(
  readFileSync(fileURLToPath(new URL('../fixtures/dev-issuer.json', import.meta.url)), 'utf8'),
) as IssuerKeyFile;

let database: Database;
let app: Express;

before(async () => {
  database = await openDatabase();
  await migrate(database);
  app = createApp(database, {
    origin,
    secure: false,
    rateLimiting: false,
    geocoding: false,
  });
});
after(async () => {
  await database.close();
});

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = response.body.csrfToken as string;
  return {
    agent,
    csrf,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) =>
      agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) =>
      agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    put: (path: string, body: object = {}) =>
      agent.put(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    delete: (path: string) =>
      agent.delete(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf),
  };
}

type Browser = Awaited<ReturnType<typeof browser>>;

const expiry = () => new Date(Date.now() + 3600_000).toISOString();

async function createRoom(
  owner: Browser,
  credential?: { dept: number; year: number },
): Promise<Room> {
  const response = await owner
    .post('/rooms', {
      title: 'Cryptography seminar',
      description: 'Materials for the class',
      expiresAt: expiry(),
      ...(credential ? { credential } : {}),
    })
    .expect(201);
  return response.body as Room;
}

async function openRoom(owner: Browser, room: Room): Promise<Room> {
  return (await owner.post(`/rooms/${room.id}/open`).expect(200)).body as Room;
}

// SnarkJS's proving curve keeps worker threads alive on Node, which stops the
// test runner from finishing, so proofs are generated in a short-lived child
// process. Browsers prove in a worker pool instead.
async function proofFor(credential: CredentialFile, roomId: string, participant: Browser): Promise<CredentialProofPayload> {
  const [room] = await database.query<{ join_code: string }>('SELECT join_code FROM rooms WHERE id = $1', [roomId]);
  const { challenge } = (await participant.post(`/join/${room.join_code}/challenge`).expect(200)).body;
  const file = join(tmpdir(), `portkey-credential-${randomUUID()}.json`);
  writeFileSync(file, JSON.stringify(credential));
  try {
    const stdout = execFileSync(
      process.execPath,
      [
        '--import',
        'tsx',
        'scripts/proveCredential.ts',
        '--credential',
        file,
        '--room',
        roomId,
        '--challenge',
        challenge,
      ],
      { cwd: root, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout) as CredentialProofPayload;
  } finally {
    rmSync(file, { force: true });
  }
}

function credential(dept = 1, year = 2026, issuer = devIssuer) {
  return issueCredential(issuer, { dept, year });
}

test('the API verifies against the issuer pinned in the committed dev key', () => {
  assert.equal(issuerPublicKey.ax, devIssuer.publicKey.ax);
  assert.equal(issuerPublicKey.ay, devIssuer.publicKey.ay);
});

test('a valid credential proof admits the holder without organizer review', async () => {
  const owner = await browser();
  const room = await createRoom(owner, { dept: 1, year: 2026 });
  assert.deepEqual(
    { dept: room.credential?.dept, year: room.credential?.year },
    { dept: 1, year: 2026 },
  );
  await openRoom(owner, room);

  const participant = await browser();
  const invitation = (await participant.get(`/join/${room.joinCode}`).expect(200))
    .body as PublicRoom;
  assert.equal(invitation.credential?.dept, 1);
  assert.equal(invitation.credential?.issuer.ax, devIssuer.publicKey.ax);

  const holder = credential();
  const proof = await proofFor(holder, room.id, participant);
  const joined = await participant
    .post(`/join/${room.joinCode}`, { label: 'Team Cedar', credentialProof: proof })
    .expect(200);
  assert.equal(joined.body.status, 'approved');
  assert.equal(joined.body.credentialVerified, true);

  await participant.get(`/rooms/${room.id}`).expect(200);

  const members = (await owner.get(`/rooms/${room.id}/members`).expect(200)).body as Member[];
  assert.equal(members.length, 1);
  assert.equal(members[0].credentialVerified, true);

  const activity = (await owner.get(`/rooms/${room.id}/activity`).expect(200))
    .body as ActivityPage;
  assert.equal(activity.events[0].kind, 'credential_proved');
  assert.equal(activity.events[0].memberLabel, 'Team Cedar');

  // The nullifier is used for one-seat enforcement, never exposed.
  const nullifier = credentialNullifier(BigInt(holder.secret), roomScope(room.id)).toString();
  for (const body of [members, activity, invitation]) {
    assert.equal(JSON.stringify(body).includes(nullifier), false);
    assert.equal(JSON.stringify(body).includes(holder.secret), false);
  }
});

test('proofs are bound to the room, requirement, and issuer', async () => {
  const owner = await browser();
  const roomA = await openRoom(owner, await createRoom(owner, { dept: 1, year: 2026 }));
  const roomB = await openRoom(owner, await createRoom(owner, { dept: 1, year: 2026 }));
  const roomC = await openRoom(owner, await createRoom(owner, { dept: 3, year: 2026 }));
  const participant = await browser();

  // A proof made for one room cannot be replayed in another, even with the same
  // requirement: the scope is a public signal.
  const cse = credential();
  const proofForA = await proofFor(cse, roomA.id, participant);
  const wrongRoom = await participant
    .post(`/join/${roomB.joinCode}`, { label: 'Team Cedar', credentialProof: proofForA })
    .expect(422);
  assert.equal(wrongRoom.body.error.code, 'CREDENTIAL_PROOF_INVALID');

  // A valid credential for another department does not satisfy the room.
  const eceProof = await proofFor(credential(3, 2026), roomA.id, participant);
  const wrongDepartment = await participant
    .post(`/join/${roomA.joinCode}`, { label: 'Team Cedar', credentialProof: eceProof })
    .expect(422);
  assert.equal(wrongDepartment.body.error.code, 'CREDENTIAL_MISMATCH');

  // A credential from an issuer the room does not accept is refused even though
  // the proof itself is valid.
  const foreign = credential(1, 2026, generateIssuer());
  const foreignProof = await proofFor(foreign, roomA.id, participant);
  const wrongIssuer = await participant
    .post(`/join/${roomA.joinCode}`, { label: 'Team Cedar', credentialProof: foreignProof })
    .expect(422);
  assert.equal(wrongIssuer.body.error.code, 'CREDENTIAL_ISSUER_MISMATCH');

  // Tampering with any public signal breaks the pairing check.
  const tampered = structuredClone(proofForA);
  tampered.publicSignals[5] = '2027';
  const invalid = await participant
    .post(`/join/${roomA.joinCode}`, { label: 'Team Cedar', credentialProof: tampered })
    .expect(422);
  assert.equal(invalid.body.error.code, 'CREDENTIAL_PROOF_INVALID');

  await participant
    .post(`/join/${roomA.joinCode}`, { label: 'Team Cedar' })
    .expect(403)
    .expect((response) => assert.equal(response.body.error.code, 'CREDENTIAL_REQUIRED'));

  const [memberships] = await database.query<{ count: number }>(
    `SELECT count(*)::int AS count FROM memberships WHERE room_id = ANY($1::uuid[])`,
    [[roomA.id, roomB.id, roomC.id]],
  );
  assert.equal(memberships.count, 0);
});

test('one credential holds one seat, and revocation does not free it', async () => {
  const owner = await browser();
  const room = await openRoom(owner, await createRoom(owner, { dept: 1, year: 2026 }));
  const holder = credential();
  const first = await browser();
  const second = await browser();
  const third = await browser();

  const admitted = await first
    .post(`/join/${room.joinCode}`, {
      label: 'Team Cedar',
      credentialProof: await proofFor(holder, room.id, first),
    })
    .expect(200);
  assert.equal(admitted.body.status, 'approved');

  const reused = await second
    .post(`/join/${room.joinCode}`, {
      label: 'Team Birch',
      credentialProof: await proofFor(holder, room.id, second),
    })
    .expect(409);
  assert.equal(reused.body.error.code, 'CREDENTIAL_ALREADY_USED');

  await owner.patch(`/rooms/${room.id}/members/${admitted.body.id}`, { status: 'revoked' }).expect(200);
  await first.get(`/rooms/${room.id}`).expect(403);
  await first
    .post(`/join/${room.joinCode}`, {
      label: 'Team Cedar',
      credentialProof: await proofFor(holder, room.id, first),
    })
    .expect(403)
    .expect((response) => assert.equal(response.body.error.code, 'ADMISSION_DENIED'));
  const stillBound = await third
    .post(`/join/${room.joinCode}`, {
      label: 'Team Willow',
      credentialProof: await proofFor(holder, room.id, third),
    })
    .expect(409);
  assert.equal(stillBound.body.error.code, 'CREDENTIAL_ALREADY_USED');

  const fresh = await third
    .post(`/join/${room.joinCode}`, {
      label: 'Team Willow',
      credentialProof: await proofFor(credential(), room.id, third),
    })
    .expect(200);
  assert.equal(fresh.body.status, 'approved');
});

test('a credential gate composes with a location restriction', async () => {
  const owner = await browser();
  const room = await createRoom(owner, { dept: 1, year: 2026 });
  await owner
    .post(`/rooms/${room.id}/geo`, { lat: 12.9345, lng: 77.5345, radiusM: 500 })
    .expect(200);
  await openRoom(owner, room);
  const participant = await browser();
  const holder = credential();
  const proof = await proofFor(holder, room.id, participant);

  await participant
    .post(`/join/${room.joinCode}`, { label: 'Team Cedar', credentialProof: proof })
    .expect(403)
    .expect((response) => assert.equal(response.body.error.code, 'GEO_REQUIRED'));

  const outside = await participant
    .post(`/join/${room.joinCode}`, {
      label: 'Team Cedar',
      credentialProof: proof,
      lat: 13.1,
      lng: 77.6,
      accuracyM: 10,
      timestamp: new Date().toISOString(),
    })
    .expect(403);
  assert.equal(outside.body.error.code, 'GEO_OUTSIDE');

  const admitted = await participant
    .post(`/join/${room.joinCode}`, {
      label: 'Team Cedar',
      credentialProof: proof,
      lat: 12.9346,
      lng: 77.5346,
      accuracyM: 10,
      timestamp: new Date().toISOString(),
    })
    .expect(200);
  assert.equal(admitted.body.status, 'approved');
  assert.equal(admitted.body.inside, true);
});

test('organizers set and clear the credential gate only before admissions', async () => {
  const owner = await browser();
  const room = await createRoom(owner);
  const participant = await browser();

  await participant
    .put(`/rooms/${room.id}/credential`, { dept: 1, year: 2026 })
    .expect(403)
    .expect((response) => assert.equal(response.body.error.code, 'OWNER_REQUIRED'));

  const gated = (await owner.put(`/rooms/${room.id}/credential`, { dept: 1, year: 2026 }).expect(200))
    .body as Room;
  assert.equal(gated.credential?.dept, 1);
  assert.equal(gated.credential?.issuer.ax, devIssuer.publicKey.ax);

  const invitation = (await participant.get(`/join/${room.joinCode}`).expect(200))
    .body as PublicRoom;
  assert.equal(invitation.credential?.year, 2026);

  const activity = (await owner.get(`/rooms/${room.id}/activity`).expect(200))
    .body as ActivityPage;
  assert.equal(activity.events[0].kind, 'room_updated');
  assert.deepEqual(activity.events[0].changedFields, ['credential']);

  await owner.delete(`/rooms/${room.id}/credential`).expect(200);
  const cleared = (await participant.get(`/join/${room.joinCode}`).expect(200))
    .body as PublicRoom;
  assert.equal(cleared.credential, null);

  await owner.put(`/rooms/${room.id}/credential`, { dept: 1, year: 2026 }).expect(200);
  await openRoom(owner, room);
  const pending = await participant
    .post(`/join/${room.joinCode}`, { label: 'Team Cedar' })
    .expect(403);
  assert.equal(pending.body.error.code, 'CREDENTIAL_REQUIRED');

  // Once somebody is admitted under the gate, the requirement is fixed.
  await owner.delete(`/rooms/${room.id}/credential`).expect(200);
  const manual = await participant
    .post(`/join/${room.joinCode}`, { label: 'Team Cedar' })
    .expect(200);
  assert.equal(manual.body.status, 'pending');
  await owner
    .patch(`/rooms/${room.id}/members/${manual.body.id}`, { status: 'approved' })
    .expect(200);
  await owner
    .put(`/rooms/${room.id}/credential`, { dept: 1, year: 2026 })
    .expect(409)
    .expect((response) => assert.equal(response.body.error.code, 'INVALID_TRANSITION'));
});


test('pending members must prove when a gate is enabled and can upgrade their original request', async () => {
  const owner = await browser();
  const room = await openRoom(owner, await createRoom(owner));
  const participant = await browser();
  const pending = (await participant.post(`/join/${room.joinCode}`, { label: 'Early arrival' }).expect(200)).body;
  await owner.put(`/rooms/${room.id}/credential`, { dept: 1, year: 2026 }).expect(200);
  const bypass = await owner.patch(`/rooms/${room.id}/members/${pending.id}`, { status: 'approved' }).expect(403);
  assert.equal(bypass.body.error.code, 'CREDENTIAL_REQUIRED');
  const proof = await proofFor(credential(), room.id, participant);
  const admitted = (await participant.post(`/join/${room.joinCode}`, {
    label: 'Early arrival', credentialProof: proof,
  }).expect(200)).body;
  assert.equal(admitted.id, pending.id);
  assert.equal(admitted.status, 'approved');
  assert.equal(admitted.credentialVerified, true);
  await participant.get(`/rooms/${room.id}`).expect(200);
  await owner.patch(`/rooms/${room.id}/members/${pending.id}`, { status: 'revoked' }).expect(200);
  await owner.delete(`/rooms/${room.id}/credential`).expect(409);
  await owner.put(`/rooms/${room.id}/credential`, { dept: 2, year: 2026 }).expect(409);
});

test('proofs cannot be front-run across sessions, reused after consumption, expired or issuer-revoked', async () => {
  const owner = await browser(), holderBrowser = await browser(), attacker = await browser();
  const room = await openRoom(owner, await createRoom(owner, { dept: 1, year: 2026 }));
  const holder = credential();
  const proof = await proofFor(holder, room.id, holderBrowser);
  const copied = await attacker.post(`/join/${room.joinCode}`, { label: 'Attacker', credentialProof: proof }).expect(422);
  assert.equal(copied.body.error.code, 'CREDENTIAL_CHALLENGE_INVALID');
  await holderBrowser.post(`/join/${room.joinCode}`, { label: 'Holder', credentialProof: proof }).expect(200);
  await holderBrowser.post(`/join/${room.joinCode}`, { label: 'Holder', credentialProof: proof }).expect(422);
  // Expiry continues to apply to previously admitted file/key/room access.
  await database.query("UPDATE memberships SET credential_expires_at = clock_timestamp() - interval '1 second' WHERE room_id = $1", [room.id]);
  await holderBrowser.get(`/rooms/${room.id}`).expect(403);
  const expired = issueCredential(devIssuer, { dept: 1, year: 2026 }, Math.floor(Date.now() / 1000) - 60);
  const expiredProof = await proofFor(expired, room.id, attacker);
  const expiredJoin = await attacker.post(`/join/${room.joinCode}`, { label: 'Expired', credentialProof: expiredProof }).expect(403);
  assert.equal(expiredJoin.body.error.code, 'CREDENTIAL_EXPIRED');
  const { signRevocation } = await import('../scripts/issuerLib.js');
  const nullifier = credentialNullifier(BigInt(holder.secret), roomScope(room.id)).toString();
  await supertest(app).post('/api/issuer/revocations').send({ roomId: room.id, nullifier, signature: signRevocation(generateIssuer(), room.id, nullifier) }).expect(403);
  const body = { roomId: room.id, nullifier, signature: signRevocation(devIssuer, room.id, nullifier) };
  await supertest(app).post('/api/issuer/revocations').send(body).expect(204);
  await supertest(app).post('/api/issuer/revocations').send(body).expect(204);
  const replay = await proofFor(holder, room.id, attacker);
  const revoked = await attacker.post(`/join/${room.joinCode}`, { label: 'Revoked', credentialProof: replay }).expect(403);
  assert.equal(revoked.body.error.code, 'CREDENTIAL_REVOKED');
});


test('institution worker delivers idempotent scoped revocations to current and future rooms', async () => {
  const { deliverRevocations } = await import('../scripts/revocationWorkerLib.js');
  const owner = await browser(), student = await browser();
  const holder = credential();
  const first = await openRoom(owner, await createRoom(owner, { dept: 1, year: 2026 }));
  const send = async (body: object) => { await supertest(app).post('/api/issuer/revocations').send(body).expect(204); };
  const delivered = await deliverRevocations(database, devIssuer, [holder], send);
  assert.ok(delivered.revocationsDelivered >= 1);
  assert.equal((await deliverRevocations(database, devIssuer, [holder], send)).revocationsDelivered, 0);
  const next = await openRoom(owner, await createRoom(owner, { dept: 1, year: 2026 }));
  assert.equal((await deliverRevocations(database, devIssuer, [holder], send)).revocationsDelivered, 1);
  for (const room of [first, next]) {
    const proof = await proofFor(holder, room.id, student);
    const rejected = await student.post(`/join/${room.joinCode}`, { label: 'Revoked credential', credentialProof: proof }).expect(403);
    assert.equal(rejected.body.error.code, 'CREDENTIAL_REVOKED');
  }
});
