import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import supertest from 'supertest';
import type { Express } from 'express';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import { runSubmissionCleanupPass, startCleanupScheduler } from '../server/cleanup.js';
import { openDatabase as openIsolatedDatabase } from '../server/database.js';
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
  return {
    agent,
    csrf,
    get: (path: string) => agent.get('/api' + path),
    post: (path: string, body: object = {}) => agent.post('/api' + path)
      .set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
  };
}

async function room(owner: Awaited<ReturnType<typeof browser>>) {
  const created = await owner.post('/rooms', {
    title: 'Retention fixture', description: '',
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }).expect(201);
  return created.body as Room;
}

async function expire(roomId: string, enabled = true) {
  await database.query(
    `UPDATE rooms SET created_at = clock_timestamp() - interval '2 seconds',
     expires_at = clock_timestamp() - interval '1 second',
     submission_cleanup_enabled = $2 WHERE id = $1`, [roomId, enabled]);
}

async function seedCompleted(roomId: string, submitterId: string) {
  const id = randomUUID();
  await database.query(
    `INSERT INTO private_submissions
     (id, room_id, submitter_id, encrypted_descriptor, chunk_count, encrypted_bytes,
      status, manifest_sha256, receipt, completed_at)
     VALUES ($1, $2, $3, $4, 1, 16, 'complete', $5, '{}'::jsonb, clock_timestamp())`,
    [id, roomId, submitterId, Buffer.from([1]), 'a'.repeat(64)]);
  await database.query(
    `INSERT INTO submission_chunks (submission_id, chunk_index, ciphertext, sha256)
     VALUES ($1, 0, $2, $3)`, [id, Buffer.alloc(16), 'b'.repeat(64)]);
  await database.query(
    `INSERT INTO submission_envelopes (submission_id, recipient_id, enc, ciphertext)
     VALUES ($1, $2, $3, $4)`, [id, submitterId, Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]), Buffer.alloc(16)]);
  return id;
}

async function seedUploading(roomId: string, submitterId: string, ageHours: number) {
  const id = randomUUID();
  await database.query(
    `INSERT INTO private_submissions (id, room_id, submitter_id, encrypted_bytes, created_at)
     VALUES ($1, $2, $3, 16, clock_timestamp() - ($4::text || ' hours')::interval)`,
    [id, roomId, submitterId, ageHours]);
  return id;
}

test('cleanup is opt-in for historical rooms and completion cascades submission ciphertext once', async () => {
  const owner = await browser();
  const disabled = await room(owner);
  const enabled = await room(owner);
  const empty = await room(owner);
  const protectedRoom = await room(owner);
  await expire(disabled.id, false);
  await expire(enabled.id);
  await expire(empty.id);
  await expire(protectedRoom.id, false);
  const copied = await owner.post('/rooms/' + disabled.id + '/duplicate', {
    title: 'Copied historical room', description: '', expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }).expect(201);
  assert.equal(copied.body.submissionCleanupEnabled, true);
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1');
  const submissionId = await seedCompleted(enabled.id, session.id);
  await seedCompleted(disabled.id, session.id);
  await seedCompleted(protectedRoom.id, session.id);

  const exposed = await owner.get('/rooms/' + disabled.id).expect(200);
  assert.equal(exposed.body.status, 'expired');
  assert.equal(exposed.body.submissionCleanupEnabled, false);
  const enabledPolicy = await owner.post('/rooms/' + disabled.id + '/submission-cleanup', {}).expect(200);
  assert.equal(enabledPolicy.body.status, 'expired');
  assert.equal(enabledPolicy.body.submissionCleanupEnabled, true);
  await owner.post('/rooms/' + disabled.id + '/submission-cleanup', {}).expect(200);
  const participant = await browser();
  await participant.post('/rooms/' + disabled.id + '/submission-cleanup', {}).expect(403);
  await owner.post('/rooms/' + disabled.id + '/submission-cleanup', { deleteAll: true }).expect(422);
  await owner.agent.post('/api/rooms/' + disabled.id + '/submission-cleanup')
    .set('Origin', origin).send({}).expect(403);
  const invalidCsrf = await owner.agent.post('/api/rooms/' + disabled.id + '/submission-cleanup')
    .set('Origin', origin).set('X-CSRF-Token', '0'.repeat(64)).send({});
  assert.equal(invalidCsrf.status, 403);
  const expiredSession = await browser();
  const [expiredSessionRow] = await database.query<{ id: string }>(
    'SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1');
  await database.query(
    `UPDATE sessions SET created_at = clock_timestamp() - interval '31 days',
     expires_at = clock_timestamp() - interval '1 second' WHERE id = $1`,
    [expiredSessionRow.id]);
  await expiredSession.post('/rooms/' + disabled.id + '/submission-cleanup', {}).expect(401);
  const [enableEvents] = await database.query<{ count: number }>(
    `SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind = 'submission_cleanup_enabled'`,
    [disabled.id]);
  assert.equal(enableEvents.count, 1);

  const concurrent = await Promise.all([
    runSubmissionCleanupPass(database),
    runSubmissionCleanupPass(database),
  ]);
  assert.equal(concurrent.reduce((sum, pass) => sum + pass.roomsCompleted, 0), 3);
  assert.equal(concurrent.reduce((sum, pass) => sum + pass.submissionsDeleted, 0), 2);
  const [privateData] = await database.query<{ count: number }>(
    'SELECT count(*)::int AS count FROM private_submissions WHERE id = $1', [submissionId]);
  const [children] = await database.query<{ chunks: number; envelopes: number }>(
    `SELECT (SELECT count(*)::int FROM submission_chunks WHERE submission_id = $1) AS chunks,
            (SELECT count(*)::int FROM submission_envelopes WHERE submission_id = $1) AS envelopes`,
    [submissionId]);
  assert.equal(privateData.count, 0);
  assert.equal(children.chunks, 0);
  assert.equal(children.envelopes, 0);
  const [completed] = await database.query<{ count: number }>(
    `SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind = 'submissions_purged'`,
    [enabled.id]);
  assert.equal(completed.count, 1);
  const [disabledCount] = await database.query<{ count: number }>(
    'SELECT count(*)::int AS count FROM private_submissions WHERE room_id = $1', [disabled.id]);
  assert.equal(disabledCount.count, 0);
  const [protectedCount] = await database.query<{ count: number }>(
    'SELECT count(*)::int AS count FROM private_submissions WHERE room_id = $1', [protectedRoom.id]);
  assert.equal(protectedCount.count, 1);
  const [protectedStatus] = await database.query<{ purged: Date | null }>(
    'SELECT submissions_purged_at AS purged FROM rooms WHERE id = $1', [protectedRoom.id]);
  assert.equal(protectedStatus.purged, null);
  assert.equal((await runSubmissionCleanupPass(database)).roomsCompleted, 0);
});

test('24-hour incomplete reclamation is proactive, bounded by state, and preserves fresh uploads', async () => {
  const owner = await browser();
  const activeRoom = await room(owner);
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1');
  const staleId = await seedUploading(activeRoom.id, session.id, 25);
  const freshId = await seedUploading(activeRoom.id, session.id, 1);
  const completedId = await seedCompleted(activeRoom.id, session.id);

  const result = await runSubmissionCleanupPass(database);
  assert.equal(result.staleUploadsDeleted, 1);
  assert.equal(result.staleBytesReclaimed, 16);
  const [remaining] = await database.query<{ count: number }>(
    'SELECT count(*)::int AS count FROM private_submissions WHERE id = ANY($1::uuid[])',
    [[staleId, freshId, completedId]]);
  assert.equal(remaining.count, 2);
});

test('early closure does not trigger room cleanup; reaching the deadline does', async () => {
  const owner = await browser();
  const closed = await room(owner);
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1');
  await seedCompleted(closed.id, session.id);
  await owner.post('/rooms/' + closed.id + '/close', {}).expect(200);
  await runSubmissionCleanupPass(database);
  const [beforeDeadline] = await database.query<{ purged: Date | null }>(
    'SELECT submissions_purged_at AS purged FROM rooms WHERE id = $1', [closed.id]);
  assert.equal(beforeDeadline.purged, null);
  await expire(closed.id);
  await runSubmissionCleanupPass(database);
  const [afterDeadline] = await database.query<{ purged: Date | null }>(
    'SELECT submissions_purged_at AS purged FROM rooms WHERE id = $1', [closed.id]);
  assert.ok(afterDeadline.purged);
});

test('failed completion activity rolls back deletion and completion timestamp', async () => {
  const owner = await browser();
  const fixture = await room(owner);
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1');
  const submissionId = await seedCompleted(fixture.id, session.id);
  await expire(fixture.id);
  await database.exec(`CREATE FUNCTION reject_purge_activity() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.kind = 'submissions_purged' THEN RAISE EXCEPTION 'test rollback'; END IF;
      RETURN NEW;
    END $$`);
  await database.exec(`CREATE TRIGGER reject_purge_activity
    BEFORE INSERT ON room_activity FOR EACH ROW EXECUTE FUNCTION reject_purge_activity()`);
  await assert.rejects(runSubmissionCleanupPass(database), /test rollback/);
  await database.exec('DROP TRIGGER reject_purge_activity ON room_activity');
  await database.exec('DROP FUNCTION reject_purge_activity()');
  const [remaining] = await database.query<{ submissions: number; purged: Date | null }>(
    `SELECT (SELECT count(*)::int FROM private_submissions WHERE id = $1) AS submissions,
            submissions_purged_at AS purged FROM rooms WHERE id = $2`,
    [submissionId, fixture.id]);
  assert.equal(remaining.submissions, 1);
  assert.equal(remaining.purged, null);
});

test('deadline is rechecked after the cleanup candidate snapshot', async () => {
  const owner = await browser();
  const fixture = await room(owner);
  const [session] = await database.query<{ id: string }>(
    'SELECT id FROM sessions ORDER BY created_at DESC LIMIT 1');
  const submissionId = await seedCompleted(fixture.id, session.id);
  await expire(fixture.id);
  const underlyingQuery = database.query.bind(database);
  let movedDeadline = false;
  const racingDatabase: Database = {
    query: async <T>(sql: string, parameters?: unknown[]) => {
      const rows = await underlyingQuery<T>(sql, parameters);
      if (!movedDeadline && sql.includes('FROM rooms WHERE submission_cleanup_enabled')) {
        movedDeadline = true;
        await database.query(
          'UPDATE rooms SET expires_at = clock_timestamp() + interval \'1 hour\' WHERE id = $1',
          [fixture.id]);
      }
      return rows;
    },
    exec: (sql: string) => database.exec(sql),
    transaction: (work) => database.transaction(work),
    close: () => Promise.resolve(),
  };
  await runSubmissionCleanupPass(racingDatabase);
  assert.equal(movedDeadline, true);
  const [remaining] = await database.query<{ submissions: number; purged: Date | null }>(
    `SELECT (SELECT count(*)::int FROM private_submissions WHERE id = $1) AS submissions,
            submissions_purged_at AS purged FROM rooms WHERE id = $2`,
    [submissionId, fixture.id]);
  assert.equal(remaining.submissions, 1);
  assert.equal(remaining.purged, null);
});

test('cleanup scheduler retries after failure, does not overlap, and drains on stop', async () => {
  let timer: (() => void) | undefined;
  let calls = 0;
  let release: (() => void) | undefined;
  let active = 0;
  let maxActive = 0;
  const scheduler = startCleanupScheduler(async () => {
    calls++;
    if (calls === 1) throw new Error('retry');
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise<void>((resolve) => { release = resolve; });
    active--;
  }, {
    setTimer: ((callback: TimerHandler) => { timer = callback as () => void; return 1 as unknown as ReturnType<typeof setTimeout>; }) as unknown as typeof setTimeout,
    clearTimer: (() => { timer = undefined; }) as typeof clearTimeout,
  });
  await new Promise((resolve) => setImmediate(resolve));
  timer!();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 2);
  timer?.();
  assert.equal(maxActive, 1);
  let stopped = false;
  const stopping = scheduler.stop().then(() => { stopped = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(stopped, false);
  release!();
  await stopping;
  assert.equal(active, 0);
  assert.equal(timer, undefined);
});

test('migration preserves existing rooms with cleanup disabled and enables new rows by default', async () => {
  const oldDatabase = await openIsolatedDatabase();
  try {
    const directory = new URL('../server/migrations/', import.meta.url);
    const names = (await readdir(directory)).filter((name) => /^00[1-4]_.*\.sql$/.test(name)).sort();
    await oldDatabase.exec(`CREATE TABLE schema_migrations (
      name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
    )`);
    for (const name of names) {
      const sql = (await readFile(new URL(name, directory), 'utf8')).replace(/\r\n/g, '\n');
      await oldDatabase.exec(sql);
      await oldDatabase.query(
        'INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)',
        [name, createHash('sha256').update(sql).digest('hex')]);
    }
    const ownerId = randomUUID();
    await oldDatabase.query(
      'INSERT INTO sessions (id, token_hash, expires_at) VALUES ($1, $2, clock_timestamp() + interval \'30 days\')',
      [ownerId, 'c'.repeat(64)]);
    await oldDatabase.query(
      `INSERT INTO rooms (id, owner_id, join_code, title, expires_at)
       VALUES ($1, $2, $3, 'Historical', clock_timestamp() + interval '1 day')`,
      [randomUUID(), ownerId, 'h'.repeat(16)]);
    await migrate(oldDatabase);
    const [legacy] = await oldDatabase.query<{ enabled: boolean }>(
      "SELECT submission_cleanup_enabled AS enabled FROM rooms WHERE title = 'Historical'");
    assert.equal(legacy.enabled, false);
    const [newRoom] = await oldDatabase.query<{ enabled: boolean }>(
      `INSERT INTO rooms (id, owner_id, join_code, title, expires_at)
       VALUES ($1, $2, $3, 'New', clock_timestamp() + interval '1 day')
       RETURNING submission_cleanup_enabled AS enabled`,
      [randomUUID(), ownerId, 'n'.repeat(16)]);
    assert.equal(newRoom.enabled, true);
    const checksums = await oldDatabase.query<{ name: string; checksum: string }>(
      "SELECT name, checksum FROM schema_migrations WHERE name IN ('001_initial.sql', '002_room_activity.sql', '003_private_submissions.sql', '004_submission_limits.sql')");
    assert.equal(checksums.length, 4);
    for (const row of checksums) {
      const sql = (await readFile(new URL(row.name, directory), 'utf8')).replace(/\r\n/g, '\n');
      assert.equal(row.checksum.trim(), createHash('sha256').update(sql).digest('hex'));
    }
  } finally {
    await oldDatabase.close();
  }
});
