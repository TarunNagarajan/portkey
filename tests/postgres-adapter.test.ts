import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import supertest from 'supertest';
import { createApp } from '../server/app.js';
import { openDatabase } from '../server/database.js';
import { migrate } from '../server/migrations.js';

const enabled = process.env.PORTKEY_RUN_POSTGRES_TESTS === '1';
test('PostgreSQL adapter applies real migrations and preserves transaction guarantees', { skip: !enabled }, async () => {
  const connectionString = process.env.PORTKEY_TEST_DATABASE_URL;
  assert.ok(connectionString, 'Set PORTKEY_TEST_DATABASE_URL to a dedicated local test database.');
  const target = new URL(connectionString);
  assert.ok(['127.0.0.1', 'localhost', '::1'].includes(target.hostname), 'PostgreSQL validation only runs against loopback.');
  assert.match(decodeURIComponent(target.pathname.slice(1)), /(?:^|[_-])test(?:[_-]|$)/i, 'Database name must clearly identify a test database.');

  const schema = `portkey_test_${randomUUID().replaceAll('-', '')}`;
  const legacySchema = `portkey_test_${randomUUID().replaceAll('-', '')}`;
  const admin = new Pool({ connectionString, max: 1 });
  let database: Awaited<ReturnType<typeof openDatabase>> | undefined;
  let legacyDatabase: Awaited<ReturnType<typeof openDatabase>> | undefined;
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.query(`CREATE SCHEMA "${legacySchema}"`);
    const scoped = new URL(connectionString);
    scoped.searchParams.set('options', `-c search_path=${schema}`);
    database = await openDatabase({ url: scoped.toString() });

    await Promise.all([migrate(database), migrate(database)]);
    const applied = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM schema_migrations');
    assert.ok(applied[0].count > 0, 'Expected the repository SQL migrations to be recorded.');

    await assert.rejects(database.transaction(async tx => {
      await tx.exec('CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY)');
      throw new Error('intentional PostgreSQL rollback check');
    }), /intentional PostgreSQL rollback check/);
    const rolledBack = await database.query<{ exists: boolean }>("SELECT to_regclass('rollback_probe') IS NOT NULL AS exists");
    assert.equal(rolledBack[0].exists, false, 'Failed transaction must roll back its DDL.');

    await database.exec('CREATE TABLE race_probe (id INTEGER PRIMARY KEY)');
    const results = await Promise.allSettled([
      database.transaction(async tx => { await tx.query('INSERT INTO race_probe(id) VALUES ($1)', [1]); }),
      database.transaction(async tx => { await tx.query('INSERT INTO race_probe(id) VALUES ($1)', [1]); }),
    ]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(results.filter(result => result.status === 'rejected').length, 1);
    const rows = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM race_probe');
    assert.equal(rows[0].count, 1);

    const origin = 'http://localhost:5173';
    const app = createApp(database, { origin, secure: false, rateLimiting: false });
    async function browser() {
      const agent = supertest.agent(app);
      const session = await agent.post('/api/session').set('Origin', origin).expect(200);
      const cookieHeader = session.headers['set-cookie'];
      const cookie = Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader;
      const token = cookie.split(';')[0].split('=')[1];
      const [stored] = await database!.query<{ id: string }>(
        'SELECT id FROM sessions WHERE token_hash = $1',
        [createHash('sha256').update(token).digest('hex')],
      );
      const csrf = session.body.csrfToken as string;
      return {
        id: stored.id,
        post: (path: string, body: object = {}) => agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
      };
    }
    const owner = await browser();
    const room = await owner.post('/rooms', {
      title: 'PostgreSQL race check', description: 'Temporary validation room',
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(), admissionPolicy: 'pass',
    }).expect(201).then(response => response.body as { id: string; joinCode: string });
    await owner.post(`/rooms/${room.id}/open`).expect(200);
    const issued = await owner.post(`/rooms/${room.id}/passes`, { count: 1 }).expect(201);
    const pass = issued.body.passes[0] as { id: string; token: string };
    const first = await browser();
    const second = await browser();
    const claims = await Promise.all([
      first.post(`/join/${room.joinCode}/redeem`, { token: pass.token, label: 'First browser' }),
      second.post(`/join/${room.joinCode}/redeem`, { token: pass.token, label: 'Second browser' }),
    ]);
    assert.deepEqual(claims.map(response => response.status).sort(), [200, 403]);
    const [claimCount] = await database.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM room_activity WHERE room_id = $1 AND kind = 'pass_redeemed'",
      [room.id],
    );
    assert.equal(claimCount.count, 1, 'Only one browser may consume the one-use pass.');

    const legacyUrl = new URL(connectionString);
    legacyUrl.searchParams.set('options', `-c search_path=${legacySchema}`);
    legacyDatabase = await openDatabase({ url: legacyUrl.toString() });
    await legacyDatabase.exec('CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())');
    const migrationDirectory = fileURLToPath(new URL('../server/migrations/', import.meta.url));
    const oldMigrations = (await readdir(migrationDirectory)).filter(name => /^0(0[1-9]|10)_.*\.sql$/.test(name)).sort();
    assert.equal(oldMigrations.length, 10, 'Expected legacy migrations 001 through 010.');
    for (const name of oldMigrations) {
      const sql = (await readFile(`${migrationDirectory}/${name}`, 'utf8')).replace(/\r\n/g, '\n');
      await legacyDatabase.exec(sql);
      await legacyDatabase.query('INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)', [name, createHash('sha256').update(sql).digest('hex')]);
    }
    const ownerId = randomUUID();
    const roomId = randomUUID();
    await legacyDatabase.query('INSERT INTO sessions(id, token_hash, expires_at) VALUES($1, $2, clock_timestamp() + interval \'1 day\')', [ownerId, randomBytes(32).toString('hex')]);
    await legacyDatabase.query('INSERT INTO rooms(id, owner_id, join_code, title, expires_at) VALUES($1, $2, $3, $4, clock_timestamp() + interval \'1 hour\')', [roomId, ownerId, randomBytes(12).toString('base64url'), 'Preserved legacy room']);
    await Promise.all([migrate(legacyDatabase), migrate(legacyDatabase)]);
    const [preserved] = await legacyDatabase.query<{ title: string }>('SELECT title FROM rooms WHERE id=$1', [roomId]);
    assert.equal(preserved.title, 'Preserved legacy room', 'Concurrent forward migrations must preserve existing room data.');
    const [newMigration] = await legacyDatabase.query<{ count: number }>("SELECT count(*)::int AS count FROM schema_migrations WHERE name='011_organizer_accounts.sql'");
    assert.equal(newMigration.count, 1, 'The forward migration must be recorded once.');
  } finally {
    await legacyDatabase?.close();
    await database?.close();
    try {
      await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
      await admin.query(`DROP SCHEMA IF EXISTS "${legacySchema}" CASCADE`);
    }
    finally { await admin.end(); }
  }
});
