import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import type { Express } from 'express';
import { CipherSuite, Aes256Gcm, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import type { Room } from '../shared/rooms.js';

const origin = 'http://localhost:5173';
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
let database: Database;
let app: Express;

before(async () => { database = await openDatabase(); await migrate(database); app = createApp(database, { origin, secure: false, rateLimiting: false }); });
after(async () => { await database.close(); });

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = response.body.csrfToken as string;
  return {
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    patch: (path: string, body: object) => agent.patch(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    put: (path: string, body: Buffer | object, type?: string) => {
      const req = agent.put(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf);
      return type ? req.set('Content-Type', type).send(body as Buffer) : req.send(body as object);
    },
  };
}

const roomInput = () => ({ title: 'Inbox room', description: '', expiresAt: new Date(Date.now() + 3600_000).toISOString() });
async function makeRoom(owner: Awaited<ReturnType<typeof browser>>): Promise<Room> {
  const created = (await owner.post('/rooms', roomInput()).expect(201)).body as Room;
  return (await owner.post(`/rooms/${created.id}/open`).expect(200)).body as Room;
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
  await participant.post(`/join/${room.joinCode}`, { label: 'Participant' }).expect(200);
  const members = await owner.get(`/rooms/${room.id}/members`).expect(200);
  await owner.patch(`/rooms/${room.id}/members/${members.body[0].id}`, { status: 'approved' }).expect(200);
  const ownerKey = await createPublicKey();
  const participantKey = await createPublicKey();
  await owner.post(`/rooms/${room.id}/submissions/owner-key`, { publicKey: base64(ownerKey) }).expect(201);
  await owner.post(`/rooms/${room.id}/submissions/owner-key`, { publicKey: base64(await createPublicKey()) }).expect(409);
  await participant.post(`/rooms/${room.id}/submissions/submitter-key`, { publicKey: base64(participantKey) }).expect(201);
  await outsider.post(`/rooms/${room.id}/submissions/submitter-key`, { publicKey: base64(await createPublicKey()) }).expect(403);
  await outsider.get(`/rooms/${room.id}/submissions`).expect(403);
  const uploadId = randomUUID();
  const created = await participant.post(`/rooms/${room.id}/submissions`, { uploadId }).expect(201);
  assert.equal((await participant.post(`/rooms/${room.id}/submissions`, { uploadId }).expect(201)).body.id, created.body.id);
  const descriptor = Buffer.alloc(69, 7);
  const enc = Buffer.alloc(65, 4);
  const envelope = { enc: enc.toString('base64'), ciphertext: Buffer.alloc(16, 8).toString('base64') };
  const metadata = { descriptor: descriptor.toString('base64'), ownerEnvelope: envelope, submitterEnvelope: envelope };
  await participant.put(`/rooms/${room.id}/submissions/${created.body.id}/metadata`, metadata).expect(204);
  await participant.put(`/rooms/${room.id}/submissions/${created.body.id}/metadata`, metadata).expect(204);
  const chunk = Buffer.alloc(16, 9);
  await participant.put(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`, chunk, 'application/octet-stream').expect(201);
  await participant.put(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`, chunk, 'application/octet-stream').expect(200);
  await participant.put(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`, Buffer.alloc(16, 1), 'application/octet-stream').expect(409);
  const digest = sha256(chunk);
  const manifest = sha256(Buffer.concat([descriptor, digest])).toString('hex');
  const completed = await participant.post(`/rooms/${room.id}/submissions/${created.body.id}/complete`, { chunkCount: 1, manifestSha256: manifest }).expect(200);
  const recovered = await participant.post(`/rooms/${room.id}/submissions`, { uploadId }).expect(201);
  assert.equal(recovered.body.complete, true);
  assert.deepEqual(recovered.body.receipt, completed.body.receipt);
  const listing = await participant.get(`/rooms/${room.id}/submissions`).expect(200);
  assert.equal(listing.body.submissions.length, 1);
  assert.equal((await owner.get(`/rooms/${room.id}/submissions`).expect(200)).body.submissions.length, 1);
  await outsider.get(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`).expect(403);
  const downloaded = await participant.get(`/rooms/${room.id}/submissions/${created.body.id}/chunks/0`).expect(200);
  assert.deepEqual(downloaded.body, chunk);
  await owner.post(`/rooms/${room.id}/close`).expect(200);
  await owner.get(`/rooms/${room.id}/submissions`).expect(410);
});

test('submission start and chunk writes require origin, CSRF and current approved membership', async () => {
  const owner = await browser();
  const participant = await browser();
  const room = await makeRoom(owner);
  await participant.post(`/join/${room.joinCode}`, { label: 'Participant' }).expect(200);
  const member = (await owner.get(`/rooms/${room.id}/members`).expect(200)).body[0];
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'approved' }).expect(200);
  await owner.post(`/rooms/${room.id}/submissions/owner-key`, { publicKey: base64(await createPublicKey()) }).expect(201);
  await participant.post(`/rooms/${room.id}/submissions/submitter-key`, { publicKey: base64(await createPublicKey()) }).expect(201);
  const start = await participant.post(`/rooms/${room.id}/submissions`, { uploadId: randomUUID() }).expect(201);
  await owner.patch(`/rooms/${room.id}/members/${member.id}`, { status: 'revoked' }).expect(200);
  await participant.put(`/rooms/${room.id}/submissions/${start.body.id}/chunks/0`, Buffer.alloc(16), 'application/octet-stream').expect(403);
  await participant.post(`/rooms/${room.id}/submissions`, { uploadId: randomUUID() }).expect(403);
});
