import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createHash, randomUUID } from "node:crypto";
import supertest from "supertest";
import type { Express } from "express";
import { createApp } from "../server/app.js";
import { openDatabase, type Database } from "../server/database.js";
import { migrate } from "../server/migrations.js";
import { runSubmissionCleanupPass } from "../server/cleanup.js";

const origin = "http://localhost:5173";
let db: Database, app: Express;
before(async () => {
  db = await openDatabase();
  await migrate(db);
  app = createApp(db, { origin, secure: false, rateLimiting: false });
});
after(async () => db.close());
async function client() {
  const agent = supertest.agent(app);
  const s = await agent.post("/api/session").set("Origin", origin).expect(200);
  const csrf = s.body.csrfToken;
  return {
    agent,
    post: (p: string, b: object) =>
      agent
        .post("/api" + p)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send(b),
    put: (p: string, b: Buffer) =>
      agent
        .put("/api" + p)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .set("Content-Type", "application/octet-stream")
        .send(b),
    delete: (p: string) =>
      agent
        .delete("/api" + p)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf),
    get: (p: string) => agent.get("/api" + p),
  };
}
async function makeRoom(c: Awaited<ReturnType<typeof client>>) {
  return (
    await c
      .post("/rooms", {
        title: "Shared files",
        description: "",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      })
      .expect(201)
  ).body;
}
async function openRoom(c: Awaited<ReturnType<typeof client>>, id: string) {
  await c.post(`/rooms/${id}/open`, {}).expect(200);
}

test("room file key is write-once and private submissions stay behind their existing routes", async () => {
  const owner = await client(),
    room = await makeRoom(owner),
    fingerprint = "a".repeat(64);
  assert.deepEqual(
    (await owner.get(`/rooms/${room.id}/files/key`).expect(200)).body,
    { fingerprint: null },
  );
  await owner.post(`/rooms/${room.id}/files/key`, { fingerprint }).expect(201);
  assert.deepEqual(
    (await owner.get(`/rooms/${room.id}/files/key`).expect(200)).body,
    { fingerprint },
  );
  await owner
    .post(`/rooms/${room.id}/files/key`, { fingerprint: "b".repeat(64) })
    .expect(409);
  await owner.get(`/rooms/${room.id}/files`).expect(410);
  await openRoom(owner, room.id);
  assert.deepEqual(
    (await owner.get(`/rooms/${room.id}/submissions`).expect(200)).body
      .submissions,
    [],
  );
});

test("an unapproved session cannot read or register the shared file key", async () => {
  const owner = await client(),
    room = await makeRoom(owner),
    stranger = await client();
  await openRoom(owner, room.id);
  await owner
    .post(`/rooms/${room.id}/files/key`, { fingerprint: "c".repeat(64) })
    .expect(201);
  await stranger.get(`/rooms/${room.id}/files/key`).expect(403);
  await stranger.get(`/rooms/${room.id}/files`).expect(403);
  await stranger
    .post(`/rooms/${room.id}/files/key`, { fingerprint: "d".repeat(64) })
    .expect(403);
});

test("shared file routes enforce fresh inside-geofence state for admitted attendees", async () => {
  const owner = await client();
  const room = await makeRoom(owner);
  await openRoom(owner, room.id);
  await db.query(
    "UPDATE rooms SET geo_lat=20,geo_lng=77,geo_radius_m=500 WHERE id=$1",
    [room.id],
  );
  const participant = await client();
  const [session] = await db.query<{ id: string }>(
    "SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1",
  );
  const membershipId = randomUUID();
  await db.query(
    `INSERT INTO memberships(id,room_id,session_id,label,status,decided_at,last_inside,last_checked_at)
     VALUES($1,$2,$3,'Attendee','approved',clock_timestamp(),true,clock_timestamp()-interval '10 minutes')`,
    [membershipId, room.id, session.id],
  );
  await participant
    .get(`/rooms/${room.id}/files`)
    .expect(403)
    .then((response) => assert.equal(response.body.error.code, "GEO_STALE"));
  await db.query(
    "UPDATE memberships SET last_inside=false,last_checked_at=clock_timestamp() WHERE id=$1",
    [membershipId],
  );
  await participant
    .get(`/rooms/${room.id}/files`)
    .expect(403)
    .then((response) => assert.equal(response.body.error.code, "GEO_OUTSIDE"));
  await db.query(
    "UPDATE memberships SET last_inside=true,last_checked_at=clock_timestamp() WHERE id=$1",
    [membershipId],
  );
  await participant.get(`/rooms/${room.id}/files`).expect(200);
});

test("owner uploads encrypted chunks with idempotent start, chunk retry, completion, and room audience listing", async () => {
  const owner = await client(),
    room = await makeRoom(owner);
  await openRoom(owner, room.id);
  const fingerprint = "e".repeat(64),
    id = randomUUID(),
    descriptor = Buffer.from("opaque encrypted descriptor"),
    ciphertext = Buffer.alloc(16, 7);
  await owner.post(`/rooms/${room.id}/files/key`, { fingerprint }).expect(201);
  const body = {
    id,
    keyFingerprint: fingerprint,
    descriptor: descriptor.toString("base64"),
    chunkCount: 1,
    encryptedBytes: 16,
  };
  await owner
    .post(`/rooms/${room.id}/files`, body)
    .expect(201)
    .then((r) => assert.equal(r.body.complete, false));
  await owner
    .post(`/rooms/${room.id}/files`, body)
    .expect(201)
    .then((r) => assert.deepEqual(r.body.uploadedChunks, []));
  const chunkPath = `/rooms/${room.id}/files/${id}/chunks/0`;
  await owner.put(chunkPath, ciphertext).expect(200);
  await owner
    .put(chunkPath, ciphertext)
    .expect(200)
    .then((r) => assert.equal(r.body.retry, true));
  const chunkHash = createHash("sha256").update(ciphertext).digest();
  const manifest = createHash("sha256")
    .update(descriptor)
    .update(chunkHash)
    .digest("hex");
  await owner
    .post(`/rooms/${room.id}/files/${id}/complete`, {
      manifestSha256: "0".repeat(64),
    })
    .expect(422);
  const completed = await owner
    .post(`/rooms/${room.id}/files/${id}/complete`, {
      manifestSha256: manifest,
    })
    .expect(200);
  assert.equal(completed.body.receipt.manifestSha256, manifest);
  await owner
    .post(`/rooms/${room.id}/files/${id}/complete`, {
      manifestSha256: manifest,
    })
    .expect(200);
  const page = await owner.get(`/rooms/${room.id}/files`).expect(200);
  assert.equal(page.body.files.length, 1);
  assert.equal(page.body.files[0].descriptor, descriptor.toString("base64"));
  assert.deepEqual(
    (await owner.get(`/rooms/${room.id}/submissions`).expect(200)).body
      .submissions,
    [],
  );
  const downloaded = await owner
    .get(`/rooms/${room.id}/files/${id}/chunks/0`)
    .expect(200);
  assert.equal(
    downloaded.headers["x-ciphertext-sha256"],
    createHash("sha256").update(ciphertext).digest("hex"),
  );
  assert.deepEqual(downloaded.body, ciphertext);
  const corruptedCiphertext = Buffer.alloc(16, 8);
  await db.query(
    "UPDATE room_file_chunks SET ciphertext=$3 WHERE file_id=$1 AND chunk_index=$2",
    [id, 0, corruptedCiphertext],
  );
  try {
    const corruptedRead = await owner
      .get(`/rooms/${room.id}/files/${id}/chunks/0`)
      .expect(500);
    assert.equal(corruptedRead.body.error.code, "FILE_CORRUPT");
  } finally {
    await db.query(
      "UPDATE room_file_chunks SET ciphertext=$3 WHERE file_id=$1 AND chunk_index=$2",
      [id, 0, ciphertext],
    );
  }
  const stranger = await client();
  await stranger.delete(`/rooms/${room.id}/files/${id}`).expect(403);
});

test("approved participants can publish to the shared audience while private inbox remains empty", async () => {
  const owner = await client();
  const room = await makeRoom(owner);
  await openRoom(owner, room.id);
  const participant = await client();
  const [session] = await db.query<{ id: string }>(
    "SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1",
  );
  await db.query(
    `INSERT INTO memberships(id,room_id,session_id,label,status,decided_at)
     VALUES($1,$2,$3,'Attendee','approved',clock_timestamp())`,
    [randomUUID(), room.id, session.id],
  );
  const fingerprint = "f".repeat(64);
  await owner.post(`/rooms/${room.id}/files/key`, { fingerprint }).expect(201);
  const id = randomUUID();
  const descriptor = Buffer.from("attendee encrypted metadata");
  const ciphertext = Buffer.alloc(16, 9);
  await participant
    .post(`/rooms/${room.id}/files`, {
      id,
      keyFingerprint: fingerprint,
      descriptor: descriptor.toString("base64"),
      chunkCount: 1,
      encryptedBytes: 16,
    })
    .expect(201);
  await participant
    .put(`/rooms/${room.id}/files/${id}/chunks/0`, ciphertext)
    .expect(200);
  const manifest = createHash("sha256")
    .update(descriptor)
    .update(createHash("sha256").update(ciphertext).digest())
    .digest("hex");
  await participant
    .post(`/rooms/${room.id}/files/${id}/complete`, {
      manifestSha256: manifest,
    })
    .expect(200);
  const shared = await owner.get(`/rooms/${room.id}/files`).expect(200);
  assert.equal(shared.body.files.length, 1);
  assert.equal(shared.body.files[0].descriptor, descriptor.toString("base64"));
  assert.deepEqual(shared.body.activeIds, [id]);
  assert.deepEqual(
    (await owner.get(`/rooms/${room.id}/submissions`).expect(200)).body
      .submissions,
    [],
  );
  await owner.delete(`/rooms/${room.id}/files/${id}`).expect(204);
  const afterDelete = await owner.get(`/rooms/${room.id}/files`).expect(200);
  assert.deepEqual(afterDelete.body.activeIds, []);
  assert.deepEqual(afterDelete.body.files, []);
  await db.query(
    "UPDATE memberships SET status='revoked',decided_at=clock_timestamp() WHERE room_id=$1 AND session_id=$2",
    [room.id, session.id],
  );
  await participant.get(`/rooms/${room.id}/files`).expect(403);
});

test("shared uploads reject invalid sizes, key mismatch, bad chunk order, and bad manifests", async () => {
  const owner = await client();
  const room = await makeRoom(owner);
  await openRoom(owner, room.id);
  const keyFingerprint = "9".repeat(64);
  await owner
    .post(`/rooms/${room.id}/files/key`, { fingerprint: keyFingerprint })
    .expect(201);
  const id = randomUUID();
  const descriptor = Buffer.from("opaque descriptor");
  const start = {
    id,
    keyFingerprint,
    descriptor: descriptor.toString("base64"),
    chunkCount: 1,
    encryptedBytes: 16,
  };
  await owner
    .post(`/rooms/${room.id}/files`, {
      ...start,
      keyFingerprint: "8".repeat(64),
    })
    .expect(409);
  await owner
    .post(`/rooms/${room.id}/files`, { ...start, chunkCount: 2 })
    .expect(422);
  await owner
    .post(`/rooms/${room.id}/files`, { ...start, descriptor: "YR==" })
    .expect(422);
  await owner.post(`/rooms/${room.id}/files`, start).expect(201);
  await owner
    .put(`/rooms/${room.id}/files/${id}/chunks/1`, Buffer.alloc(16))
    .expect(422);
  await owner
    .put(`/rooms/${room.id}/files/${id}/chunks/0`, Buffer.alloc(15))
    .expect(422);
  await owner
    .post(`/rooms/${room.id}/files/${id}/complete`, {
      manifestSha256: "a".repeat(64),
    })
    .expect(409);
  await owner.delete(`/rooms/${room.id}/files/${id}`).expect(204);
  await owner.delete(`/rooms/${room.id}/files/${id}`).expect(204);
});

test("shared file mutations stop when a room closes", async () => {
  const owner = await client();
  const room = await makeRoom(owner);
  await openRoom(owner, room.id);
  const fingerprint = "7".repeat(64);
  await owner.post(`/rooms/${room.id}/files/key`, { fingerprint }).expect(201);
  const id = randomUUID();
  await owner
    .post(`/rooms/${room.id}/files`, {
      id,
      keyFingerprint: fingerprint,
      descriptor: Buffer.from("opaque").toString("base64"),
      chunkCount: 1,
      encryptedBytes: 16,
    })
    .expect(201);
  await owner.post(`/rooms/${room.id}/close`, {}).expect(200);
  await owner
    .put(`/rooms/${room.id}/files/${id}/chunks/0`, Buffer.alloc(16))
    .expect(410);
  await owner.delete(`/rooms/${room.id}/files/${id}`).expect(410);
});

test("concurrent room file reservations share the private inbox quota", async () => {
  const owner = await client();
  const room = await makeRoom(owner);
  await openRoom(owner, room.id);
  const [session] = await db.query<{ id: string }>(
    "SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1",
  );
  for (let index = 0; index < 19; index++) {
    await db.query(
      "INSERT INTO private_submissions(id,room_id,submitter_id,encrypted_bytes) VALUES($1,$2,$3,262148000)",
      [randomUUID(), room.id, session.id],
    );
  }
  await db.query(
    "INSERT INTO private_submissions(id,room_id,submitter_id,encrypted_bytes) VALUES($1,$2,$3,262148000)",
    [randomUUID(), room.id, session.id],
  );
  await db.query(
    "INSERT INTO private_submissions(id,room_id,submitter_id,encrypted_bytes) VALUES($1,$2,$3,125749104)",
    [randomUUID(), room.id, session.id],
  );
  const fingerprint = "6".repeat(64);
  await owner.post(`/rooms/${room.id}/files/key`, { fingerprint }).expect(201);
  const makeStart = () =>
    owner.post(`/rooms/${room.id}/files`, {
      id: randomUUID(),
      keyFingerprint: fingerprint,
      descriptor: Buffer.from("opaque").toString("base64"),
      chunkCount: 1,
      encryptedBytes: 16,
    });
  const responses = await Promise.all([makeStart(), makeStart()]);
  assert.deepEqual(
    responses.map((response) => response.status).sort(),
    [201, 413],
  );
});

test("retention purges shared files with expired-room cleanup and reclaims stale uploads", async () => {
  const owner = await client();
  const room = await makeRoom(owner);
  const activeRoom = await makeRoom(owner);
  const [session] = await db.query<{ id: string }>(
    "SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1",
  );
  const oldFile = randomUUID();
  await db.query(
    `INSERT INTO room_files(id,room_id,uploader_id,descriptor,chunk_count,encrypted_bytes,
      manifest_sha256,status,completed_at,created_at)
     VALUES($1,$2,$3,$4,1,16,$5,'complete',clock_timestamp(),clock_timestamp()-interval '2 days')`,
    [oldFile, room.id, session.id, Buffer.from([1]), "a".repeat(64)],
  );
  const staleFile = randomUUID();
  await db.query(
    `INSERT INTO room_files(id,room_id,uploader_id,descriptor,chunk_count,encrypted_bytes,created_at)
     VALUES($1,$2,$3,$4,1,16,clock_timestamp()-interval '25 hours')`,
    [staleFile, activeRoom.id, session.id, Buffer.from([2])],
  );
  await db.query(
    `UPDATE rooms SET created_at=clock_timestamp()-interval '2 seconds',
      expires_at=clock_timestamp()-interval '1 second',submission_cleanup_enabled=true WHERE id=$1`,
    [room.id],
  );
  const result = await runSubmissionCleanupPass(db);
  assert.equal(result.sharedFilesDeleted, 2);
  const [remaining] = await db.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM room_files WHERE id=ANY($1::uuid[])",
    [[oldFile, staleFile]],
  );
  assert.equal(remaining.count, 0);
});
