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
import { publicJwks, rotateSigningKey, signingKey } from '../server/platformCrypto.js';

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
    const latestMigrations = await database.query<{ name: string }>(
      "SELECT name FROM schema_migrations WHERE name = ANY($1::text[]) ORDER BY name",
      [[
        '013_room_key_rotation.sql',
        '014_signing_key_rotation.sql',
        '015_custom_proof_adapters.sql',
      ]],
    );
    assert.deepEqual(latestMigrations.map(({ name }) => name), [
      '013_room_key_rotation.sql',
      '014_signing_key_rotation.sql',
      '015_custom_proof_adapters.sql',
    ]);

    const initializedKeys = await Promise.all(
      Array.from({ length: 6 }, () => signingKey(database!)),
    );
    assert.equal(new Set(initializedKeys.map(({ kid }) => kid)).size, 1);
    const [initialActive] = await database.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM platform_signing_keyring WHERE active=TRUE',
    );
    assert.equal(initialActive.count, 1);

    await database.query(
      "UPDATE platform_signing_keyring SET created_at=clock_timestamp()-interval '61 seconds' WHERE active=TRUE",
    );
    const rotationResults = await Promise.allSettled([
      rotateSigningKey(database),
      rotateSigningKey(database),
    ]);
    const successfulRotations = rotationResults.filter(
      (result): result is PromiseFulfilledResult<string> => result.status === 'fulfilled',
    );
    const rejectedRotations = rotationResults.filter(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );
    assert.equal(successfulRotations.length, 1);
    assert.equal(rejectedRotations.length, 1);
    assert.match(String(rejectedRotations[0].reason), /rotated recently/);
    const [activeSigningKey] = await database.query<{ kid: string; count: number }>(
      'SELECT kid,count(*) OVER()::int AS count FROM platform_signing_keyring WHERE active=TRUE',
    );
    assert.equal(activeSigningKey.count, 1);
    assert.equal(activeSigningKey.kid, successfulRotations[0].value);
    const [retiredSigningKey] = await database.query<{ private_pkcs8: Buffer | null }>(
      'SELECT private_pkcs8 FROM platform_signing_keyring WHERE active=FALSE ORDER BY created_at DESC LIMIT 1',
    );
    assert.equal(retiredSigningKey.private_pkcs8, null);
    assert.equal((await publicJwks(database)).keys.length, 2);

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

    await owner.post(`/rooms/${room.id}/files/key`, { fingerprint: 'a'.repeat(64) }).expect(201);
    const reservationBytes = [
      ...Array(20).fill(262148000),
      125749104,
    ] as number[];
    for (const encryptedBytes of reservationBytes) {
      await database.query(
        'INSERT INTO private_submissions(id,room_id,submitter_id,encrypted_bytes) VALUES($1,$2,$3,$4)',
        [randomUUID(), room.id, owner.id, encryptedBytes],
      );
    }
    const makeSharedReservation = () => owner.post(`/rooms/${room.id}/files`, {
      id: randomUUID(),
      keyFingerprint: 'a'.repeat(64),
      descriptor: Buffer.from('opaque PostgreSQL quota fixture').toString('base64'),
      chunkCount: 1,
      encryptedBytes: 16,
    });
    const reservationResults = await Promise.all([
      makeSharedReservation(),
      makeSharedReservation(),
    ]);
    assert.deepEqual(
      reservationResults.map(result => result.status).sort(),
      [201, 413],
      'Concurrent room file starts must reserve against the same private and shared quota under the room lock.',
    );
    const [sharedReservations] = await database.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM room_files WHERE room_id=$1 AND status='uploading'",
      [room.id],
    );
    assert.equal(sharedReservations.count, 1);

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
    const roomFileMigrations = (await readdir(migrationDirectory))
      .filter(name => /^01[12]_.*\.sql$/.test(name))
      .sort();
    for (const name of roomFileMigrations) {
      const sql = (await readFile(`${migrationDirectory}/${name}`, 'utf8')).replace(/\r\n/g, '\n');
      await legacyDatabase.exec(sql);
      await legacyDatabase.query(
        'INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)',
        [name, createHash('sha256').update(sql).digest('hex')],
      );
    }
    const legacyFingerprint = 'd'.repeat(64);
    const legacyFileId = randomUUID();
    const legacyDescriptor = Buffer.from('encrypted descriptor from migration 012');
    const legacyCiphertext = Buffer.alloc(16, 0x55);
    await legacyDatabase.query(
      'INSERT INTO room_file_keys(room_id,fingerprint) VALUES($1,$2)',
      [roomId, legacyFingerprint],
    );
    await legacyDatabase.query(
      'INSERT INTO room_files(id,room_id,uploader_id,descriptor,chunk_count,encrypted_bytes) VALUES($1,$2,$3,$4,1,16)',
      [legacyFileId, roomId, ownerId, legacyDescriptor],
    );
    await legacyDatabase.query(
      'INSERT INTO room_file_chunks(file_id,chunk_index,ciphertext,sha256) VALUES($1,0,$2,$3)',
      [legacyFileId, legacyCiphertext, createHash('sha256').update(legacyCiphertext).digest('hex')],
    );
    await Promise.all([migrate(legacyDatabase), migrate(legacyDatabase)]);
    const [preserved] = await legacyDatabase.query<{ title: string }>('SELECT title FROM rooms WHERE id=$1', [roomId]);
    assert.equal(preserved.title, 'Preserved legacy room', 'Concurrent forward migrations must preserve existing room data.');
    const latestLegacyMigrations = await legacyDatabase.query<{ name: string }>(
      "SELECT name FROM schema_migrations WHERE name = ANY($1::text[]) ORDER BY name",
      [[
        '013_room_key_rotation.sql',
        '014_signing_key_rotation.sql',
        '015_custom_proof_adapters.sql',
      ]],
    );
    assert.deepEqual(latestLegacyMigrations.map(({ name }) => name), [
      '013_room_key_rotation.sql',
      '014_signing_key_rotation.sql',
      '015_custom_proof_adapters.sql',
    ], 'All forward migrations must be recorded exactly once.');
    const [backfilled] = await legacyDatabase.query<{
      fingerprint: string;
      epoch: number;
      history_envelope: string | null;
      key_fingerprint: string;
      descriptor: Buffer;
    }>(`SELECT k.fingerprint,k.epoch,k.history_envelope,f.key_fingerprint,f.descriptor
        FROM room_file_keys k JOIN room_files f ON f.room_id=k.room_id WHERE f.id=$1`, [legacyFileId]);
    const [preservedChunk] = await legacyDatabase.query<{ ciphertext: Buffer; sha256: string }>(
      'SELECT ciphertext,sha256 FROM room_file_chunks WHERE file_id=$1 AND chunk_index=0',
      [legacyFileId],
    );
    assert.equal(backfilled.fingerprint, legacyFingerprint);
    assert.equal(backfilled.epoch, 1);
    assert.equal(backfilled.history_envelope, null);
    assert.equal(backfilled.key_fingerprint, legacyFingerprint);
    assert.deepEqual(Buffer.from(backfilled.descriptor), legacyDescriptor);
    assert.deepEqual(Buffer.from(preservedChunk.ciphertext), legacyCiphertext);
    assert.equal(preservedChunk.sha256, createHash('sha256').update(legacyCiphertext).digest('hex'));
    const [preservedMigrations] = await legacyDatabase.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM schema_migrations WHERE name=ANY($1::text[])',
      [oldMigrations],
    );
    assert.equal(preservedMigrations.count, 10, 'All legacy migrations 001 through 010 must remain recorded.');
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
