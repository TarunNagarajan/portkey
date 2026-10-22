import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import supertest from 'supertest';
import type { Express } from 'express';
import { Identity } from '@semaphore-protocol/identity';
import { Group } from '@semaphore-protocol/group';
import { generateProof } from '@semaphore-protocol/proof';
import { resolve } from 'node:path';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import type { Room } from '../shared/rooms.js';
import { workshopPolicyDigest } from '../shared/workshopProof.js';

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
  const token = (response.headers['set-cookie'] as unknown as string[])[0].split(';')[0].split('=')[1];
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions WHERE token_hash = $1',
    [createHash('sha256').update(token).digest('hex')],
  );
  return {
    sessionId: session.id,
    agent,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    put: (path: string, body: object = {}) => agent.put(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) => agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    delete: (path: string) => agent.delete(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send({}),
  };
}

type Browser = Awaited<ReturnType<typeof browser>>;

async function proofRoom(owner: Browser): Promise<Room> {
  return (await owner.post('/rooms', {
    title: 'Reusable proof room',
    description: '',
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    admissionPolicy: 'proof',
  }).expect(201)).body as Room;
}

test('reusable groups enforce ownership, one use enrollment, safe metadata and bounded draft rules', async () => {
  const owner = await browser();
  const outsider = await browser();
  const secondOwner = await browser();
  const attendee = await browser();
  const created = await owner.post('/credential-groups', { name: 'Workshop attendees', description: 'Autumn cohort' }).expect(201);
  const groupId = created.body.id as string;
  assert.equal(created.body.available, true);
  const foreignGroup = (await secondOwner.post('/credential-groups', { name: 'Foreign group' }).expect(201)).body as { id: string };
  await owner.post('/credential-groups', { name: 'Invalid', description: 'x', ownerSessionId: owner.sessionId }).expect(422);
  await outsider.get(`/credential-groups/${groupId}`).expect(404);
  await outsider.post(`/credential-groups/${groupId}/enrollments`, { count: 1 }).expect(404);
  await owner.agent.post('/api/credential-groups').set('Origin', origin).send({ name: 'Missing CSRF' }).expect(403);
  await owner.agent.post('/api/credential-groups').set('Origin', 'https://attacker.invalid').set('X-CSRF-Token', 'invalid').send({ name: 'Wrong origin' }).expect(403);

  await owner.post(`/credential-groups/${groupId}/enrollments`, { count: 21 }).expect(422);
  await owner.post(`/credential-groups/${groupId}/enrollments`, { count: 251 }).expect(422);
  const issue = await owner.post(`/credential-groups/${groupId}/enrollments`, { count: 2 }).expect(201);
  const [invite, revoked] = issue.body.enrollments as Array<{ id: string; token: string }>;
  await owner.patch(`/credential-groups/${groupId}/enrollments/${revoked.id}`, { status: 'revoked' }).expect(200);
  const identity = new Identity();
  await attendee.post(`/credentials/${groupId}/enroll`, { token: revoked.token, commitment: identity.commitment.toString() }).expect(403);
  await attendee.post(`/credentials/${groupId}/enroll`, { token: invite.token, commitment: identity.commitment.toString(), groupId }).expect(422);
  await attendee.post(`/credentials/${groupId}/enroll`, { token: invite.token, commitment: identity.commitment.toString() }).expect(200);
  await attendee.post(`/credentials/${groupId}/enroll`, { token: invite.token, commitment: identity.commitment.toString() }).expect(200)
    .expect(({ body }) => assert.equal(body.alreadyEnrolled, true));
  await attendee.post(`/credentials/${groupId}/enroll`, { token: invite.token, commitment: new Identity().commitment.toString() }).expect(403);
  await owner.post(`/credentials/${groupId}/enroll`, { token: invite.token, commitment: new Identity().commitment.toString() }).expect(403);

  const publicDescriptor = await outsider.get(`/credentials/${groupId}`).expect(200);
  assert.equal(publicDescriptor.body.credential.id, groupId);
  assert.equal(JSON.stringify(publicDescriptor.body).includes(invite.token), false);
  const ownerMetadata = await owner.get(`/credential-groups/${groupId}`).expect(200);
  assert.equal(JSON.stringify(ownerMetadata.body).includes(invite.token), false);
  assert.equal(JSON.stringify(ownerMetadata.body).includes(identity.commitment.toString()), false);
  const [stored] = await database.query<{ token_digest: Buffer; enrolled_commitment: string }>(
    'SELECT token_digest, enrolled_commitment FROM credential_group_invites WHERE id = $1', [invite.id],
  );
  assert.equal(Buffer.from(stored.token_digest).toString('hex'), createHash('sha256').update(Buffer.from(invite.token, 'base64url')).digest('hex'));
  assert.equal(stored.enrolled_commitment, identity.commitment.toString());

  const room = await proofRoom(owner);
  await owner.get(`/rooms/${room.id}/proof-rule`).expect(200).expect(({ body }) => assert.equal(body.proofRule, null));
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupId.toUpperCase()] }).expect(200)
    .expect(({ body }) => {
      assert.equal(body.proofRule.mode, 'any');
      assert.equal(body.proofRule.digest, workshopPolicyDigest([groupId]));
      assert.deepEqual(body.proofRule.groups.map((group: { id: string }) => group.id), [groupId]);
    });
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupId] }).expect(200);
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [foreignGroup.id] }).expect(403);
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupId, groupId.toUpperCase()] }).expect(422);
  await outsider.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupId] }).expect(403);
  const [auditsBeforeClear] = await database.query<{ count: number }>("SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind IN ('proof_rule_updated', 'proof_rule_cleared')", [room.id]);
  const [lastAudit] = await database.query<{ kind: string; member_label: string | null; changed_fields: string[] }>("SELECT kind, member_label, changed_fields FROM room_activity WHERE room_id = $1 ORDER BY id DESC LIMIT 1", [room.id]);
  assert.equal(lastAudit.kind, 'proof_rule_updated');
  assert.equal(lastAudit.member_label, null);
  assert.deepEqual(lastAudit.changed_fields, []);
  assert.equal(auditsBeforeClear.count, 1);
  await owner.post(`/rooms/${room.id}/enrollments`, { count: 1 }).expect(409);
  await owner.delete(`/rooms/${room.id}/proof-rule`).expect(200);
  const [auditsAfterClear] = await database.query<{ count: number }>("SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind IN ('proof_rule_updated', 'proof_rule_cleared')", [room.id]);
  assert.equal(auditsAfterClear.count, 2);
  await owner.post(`/rooms/${room.id}/enrollments`, { count: 1 }).expect(201);
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupId] }).expect(409);
  await owner.patch(`/rooms/${room.id}`, { title: room.title, description: room.description, expiresAt: room.expiresAt });
  await owner.get(`/rooms/${room.id}/proof-rule`).expect(200).expect(({ body }) => assert.equal(body.proofRule, null));
});

test('a proof rule challenges against one deterministic union and templates copy only the binding', async () => {
  const owner = await browser();
  const attendee = await browser();
  const groupA = (await owner.post('/credential-groups', { name: 'Attendees A' }).expect(201)).body as { id: string };
  const groupB = (await owner.post('/credential-groups', { name: 'Attendees B' }).expect(201)).body as { id: string };
  const identity = new Identity();
  const second = new Identity();
  for (const group of [groupA, groupB]) {
    const { token } = (await owner.post(`/credential-groups/${group.id}/enrollments`, { count: 1 }).expect(201)).body.enrollments[0] as { token: string };
    await attendee.post(`/credentials/${group.id}/enroll`, { token, commitment: identity.commitment.toString() }).expect(200);
  }
  const secondToken = (await owner.post(`/credential-groups/${groupB.id}/enrollments`, { count: 1 }).expect(201)).body.enrollments[0].token as string;
  await attendee.post(`/credentials/${groupB.id}/enroll`, { token: secondToken, commitment: second.commitment.toString() }).expect(200);
  const room = await proofRoom(owner);
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupB.id, groupA.id] }).expect(200);
  await owner.post(`/rooms/${room.id}/open`).expect(200);
  const challenge = (await attendee.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as {
    commitments: string[]; proofRule: { digest: string; groups: Array<{ id: string }> }; root: string; scope: string;
  };
  assert.equal(challenge.commitments.length, 2);
  assert.deepEqual(challenge.commitments, [identity.commitment.toString(), second.commitment.toString()].sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1));
  assert.deepEqual(challenge.proofRule.groups.map(group => group.id), [groupA.id, groupB.id].sort());
  assert.equal(challenge.proofRule.digest, workshopPolicyDigest([groupA.id, groupB.id]));
  await attendee.post(`/join/${room.joinCode}/proof-challenge`, { groupId: groupA.id }).expect(422);
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [groupA.id] }).expect(409);
  const template = (await owner.post(`/rooms/${room.id}/duplicate`, { expiresAt: new Date(Date.now() + 3_600_000).toISOString() }).expect(201)).body as Room;
  await owner.get(`/rooms/${template.id}/proof-rule`).expect(200).expect(({ body }) => assert.equal(body.proofRule.digest, challenge.proofRule.digest));
  await owner.post(`/rooms/${template.id}/open`).expect(200);
  const next = (await attendee.post(`/join/${template.joinCode}/proof-challenge`, {}).expect(200)).body;
  assert.equal(next.commitments.length, 2);
  assert.notEqual(next.scope, challenge.scope);
  assert.equal(next.proofRule.digest, challenge.proofRule.digest);
});

test('migration 009 preserves populated legacy proof and room data', async () => {
  const legacy = await openDatabase();
  try {
    await legacy.exec('CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())');
    const directory = fileURLToPath(new URL('../server/migrations/', import.meta.url));
    for (const name of ['001_initial.sql', '002_room_activity.sql', '003_private_submissions.sql', '004_submission_limits.sql', '005_submission_retention.sql', '006_geofence.sql', '007_admission_passes.sql', '008_workshop_proof_admission.sql']) {
      const sql = (await readFile(join(directory, name), 'utf8')).replace(/\r\n/g, '\n');
      await legacy.exec(sql);
      await legacy.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [name, createHash('sha256').update(sql).digest('hex')]);
    }
    const ownerId = randomUUID();
    const roomId = randomUUID();
    const inviteId = randomUUID();
    const expiry = new Date(Date.now() + 3_600_000);
    await legacy.query('INSERT INTO sessions (id, token_hash, expires_at) VALUES ($1, $2, $3)', [ownerId, 'a'.repeat(64), expiry]);
    await legacy.query('INSERT INTO rooms (id, owner_id, join_code, title, description, status, expires_at, admission_policy) VALUES ($1, $2, $3, $4, $5, \'open\', $6, \'proof\')', [roomId, ownerId, '1234567890abcdef', 'Legacy proof', '', expiry]);
    await legacy.query('INSERT INTO room_proof_invites (id, room_id, invite_number, token_digest) VALUES ($1, $2, 1, decode($3, \'hex\'))', [inviteId, roomId, 'b'.repeat(64)]);
    await legacy.query('INSERT INTO room_proof_commitments (room_id, commitment, invite_id) VALUES ($1, $2, $3)', [roomId, '1', inviteId]);
    await migrate(legacy);
    const [preserved] = await legacy.query<{ count: number; commitment: string }>('SELECT count(i.id)::int AS count, max(c.commitment) AS commitment FROM room_proof_invites i JOIN room_proof_commitments c ON c.invite_id = i.id WHERE i.room_id = $1', [roomId]);
    assert.deepEqual(preserved, { count: 1, commitment: '1' });
    const [version] = await legacy.query<{ count: number }>("SELECT count(*)::int AS count FROM schema_migrations WHERE name = '009_reusable_credential_groups.sql'");
    assert.equal(version.count, 1);
    const [column] = await legacy.query<{ count: number }>("SELECT count(*)::int AS count FROM information_schema.columns WHERE table_name = 'room_proof_challenges' AND column_name = 'policy_digest'");
    assert.equal(column.count, 1);
  } finally { await legacy.close(); }
});

test('group and invitation lifetime bounds are enforced and issuer expiry is authoritative', async () => {
  const owner = await browser();
  const attendee = await browser();
  const groups: Array<{ id: string }> = [];
  for (let index = 0; index < 32; index += 1) {
    groups.push((await owner.post('/credential-groups', { name: `Group ${index + 1}` }).expect(201)).body as { id: string });
  }
  await owner.post('/credential-groups', { name: 'Over the group cap' }).expect(409);

  const cappedGroup = groups[0];
  for (let remaining = 250; remaining > 0; remaining -= 20) {
    await owner.post(`/credential-groups/${cappedGroup.id}/enrollments`, { count: Math.min(20, remaining) }).expect(201);
  }
  await owner.post(`/credential-groups/${cappedGroup.id}/enrollments`, { count: 1 }).expect(409);
  const [invite] = await database.query<{ id: string }>('SELECT id FROM credential_group_invites WHERE group_id = $1 ORDER BY invite_number LIMIT 1', [cappedGroup.id]);
  assert.ok(invite.id);

  const expiringGroup = groups[1];
  const token = (await owner.post(`/credential-groups/${expiringGroup.id}/enrollments`, { count: 1 }).expect(201)).body.enrollments[0].token as string;
  await database.query("UPDATE sessions SET created_at = clock_timestamp() - interval '2 days', expires_at = clock_timestamp() - interval '1 second' WHERE id = $1", [owner.sessionId]);
  await attendee.get(`/credentials/${expiringGroup.id}`).expect(200).expect(({ body }) => assert.equal(body.credential.available, false));
  const identity = new Identity();
  await attendee.post(`/credentials/${expiringGroup.id}/enroll`, { token, commitment: identity.commitment.toString() }).expect(403);
});

test('explicit room and owner-session cleanup removes bound group references without fallback', async () => {
  const owner = await browser();
  const group = (await owner.post('/credential-groups', { name: 'Cleanup group' }).expect(201)).body as { id: string };
  const room = await proofRoom(owner);
  await owner.put(`/rooms/${room.id}/proof-rule`, { groupIds: [group.id] }).expect(200);
  await owner.post(`/credential-groups/${group.id}/enrollments`, { count: 1 }).expect(201);

  await database.transaction(async transaction => {
    await transaction.query('DELETE FROM rooms WHERE id = $1', [room.id]);
    await transaction.query('DELETE FROM sessions WHERE id = $1', [owner.sessionId]);
  });
  const [counts] = await database.query<{ rooms: number; groups: number; bindings: number }>(
    `SELECT
       (SELECT count(*)::int FROM rooms WHERE id = $1) AS rooms,
       (SELECT count(*)::int FROM credential_groups WHERE id = $2) AS groups,
       (SELECT count(*)::int FROM room_proof_groups WHERE room_id = $1) AS bindings`,
    [room.id, group.id],
  );
  assert.deepEqual(counts, { rooms: 0, groups: 0, bindings: 0 });
});

test('real union proofs admit members from either group across rooms while snapshot, scope and nullifier rules hold', async () => {
  const owner = await browser();
  const attendeeA = await browser();
  const attendeeB = await browser();
  const attendeeGrowth = await browser();
  const nonmember = await browser();
  const groupA = (await owner.post('/credential-groups', { name: 'Group A' }).expect(201)).body as { id: string };
  const groupB = (await owner.post('/credential-groups', { name: 'Group B' }).expect(201)).body as { id: string };
  const identityA = new Identity();
  const identityB = new Identity();
  async function enroll(groupId: string, participant: Browser, identity: Identity) {
    const { token } = (await owner.post(`/credential-groups/${groupId}/enrollments`, { count: 1 }).expect(201)).body.enrollments[0] as { token: string };
    await participant.post(`/credentials/${groupId}/enroll`, { token, commitment: identity.commitment.toString() }).expect(200);
  }
  await enroll(groupA.id, attendeeA, identityA);
  await enroll(groupB.id, attendeeB, identityB);
  const room1 = await proofRoom(owner);
  await owner.put(`/rooms/${room1.id}/proof-rule`, { groupIds: [groupA.id, groupB.id] }).expect(200);
  await owner.post(`/rooms/${room1.id}/open`).expect(200);
  type Challenge = { challengeId: string; root: string; scope: string; message: string; depth: number; commitments: string[]; expiresAt: string; proofRule: { digest: string } };
  async function challenge(participant: Browser, room: Room) {
    return (await participant.post(`/join/${room.joinCode}/proof-challenge`, {}).expect(200)).body as Challenge;
  }
  async function proof(identity: Identity, value: Challenge) {
    const group = new Group(value.commitments.map(BigInt));
    assert.equal(group.root.toString(), value.root);
    assert.notEqual(group.indexOf(identity.commitment), -1);
    return generateProof(identity, group, value.message, value.scope, value.depth, {
      wasm: resolve('public/zk/semaphore-10.wasm'),
      zkey: resolve('public/zk/semaphore-10.zkey'),
    });
  }
  const snapshotA = await challenge(attendeeA, room1);
  const growthIdentity = new Identity();
  await enroll(groupB.id, attendeeGrowth, growthIdentity);
  const proofA = await proof(identityA, snapshotA);
  await attendeeA.post(`/join/${room1.joinCode}/prove`, { challengeId: snapshotA.challengeId, proof: proofA }).expect(200);
  const challengeB = await challenge(attendeeB, room1);
  assert.equal(challengeB.commitments.length, 3);
  const proofB = await proof(identityB, challengeB);
  await attendeeB.post(`/join/${room1.joinCode}/prove`, { challengeId: challengeB.challengeId, proof: proofB }).expect(200);
  const [room1Nullifier] = await database.query<{ nullifier: string }>('SELECT nullifier FROM room_proof_nullifiers WHERE room_id = $1 AND session_id = $2', [room1.id, attendeeA.sessionId]);
  assert.ok(room1Nullifier);

  const room2 = await proofRoom(owner);
  await owner.put(`/rooms/${room2.id}/proof-rule`, { groupIds: [groupB.id, groupA.id] }).expect(200);
  await owner.post(`/rooms/${room2.id}/open`).expect(200);
  const challengeRoom2 = await challenge(attendeeA, room2);
  const proofRoom2 = await proof(identityA, challengeRoom2);
  assert.notEqual(challengeRoom2.scope, snapshotA.scope);
  await attendeeA.post(`/join/${room2.joinCode}/prove`, { challengeId: challengeRoom2.challengeId, proof: proofRoom2 }).expect(200);
  const [room2Nullifier] = await database.query<{ nullifier: string }>('SELECT nullifier FROM room_proof_nullifiers WHERE room_id = $1 AND session_id = $2', [room2.id, attendeeA.sessionId]);
  assert.ok(room2Nullifier);
  assert.notEqual(room2Nullifier.nullifier, room1Nullifier.nullifier);

  await attendeeA.post(`/join/${room2.joinCode}/prove`, { challengeId: snapshotA.challengeId, proof: proofA }).expect(403);
  const outsideChallenge = await challenge(nonmember, room2);
  await nonmember.post(`/join/${room2.joinCode}/prove`, { challengeId: outsideChallenge.challengeId, proof: proofA }).expect(403);
  const tampered = await challenge(attendeeGrowth, room2);
  const memberProofForOutsiderChallenge = await proof(identityA, tampered);
  await database.query('UPDATE room_proof_challenges SET policy_digest = $2 WHERE id = $1', [tampered.challengeId, 'f'.repeat(64)]);
  await attendeeGrowth.post(`/join/${room2.joinCode}/prove`, { challengeId: tampered.challengeId, proof: memberProofForOutsiderChallenge }).expect(403);

  const [member] = await database.query<{ id: string }>('SELECT id FROM memberships WHERE room_id = $1 AND session_id = $2', [room1.id, attendeeA.sessionId]);
  await owner.patch(`/rooms/${room1.id}/members/${member.id}`, { status: 'revoked' }).expect(200);
  await attendeeA.post(`/join/${room1.joinCode}/prove`, { challengeId: snapshotA.challengeId, proof: proofA }).expect(403);
  await database.query('DELETE FROM memberships WHERE session_id = $1', [attendeeA.sessionId]);
  await database.query('DELETE FROM sessions WHERE id = $1', [attendeeA.sessionId]);
  const [permanent] = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM room_proof_nullifiers WHERE room_id = $1 AND nullifier = $2', [room1.id, room1Nullifier.nullifier]);
  assert.equal(permanent.count, 1);
  const replayBrowser = await browser();
  const replayChallenge = await challenge(replayBrowser, room1);
  const replayProof = await proof(identityA, replayChallenge);
  await replayBrowser.post(`/join/${room1.joinCode}/prove`, { challengeId: replayChallenge.challengeId, proof: replayProof }).expect(403);
  const [afterReplay] = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM room_proof_nullifiers WHERE room_id = $1 AND nullifier = $2', [room1.id, room1Nullifier.nullifier]);
  assert.equal(afterReplay.count, 1);
});
