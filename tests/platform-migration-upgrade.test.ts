import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';

let database: Database | undefined;
let directory = '';

after(async () => {
  await database?.close();
  if (directory) await rm(directory, { recursive: true, force: true });
});

test('migrations 010 through 015 preserve populated legacy room, file, and platform records', async () => {
  directory = await mkdtemp(join(tmpdir(), 'portkey-platform-migration-'));
  database = await openDatabase({ dataDir: directory });
  await database.exec(`CREATE TABLE schema_migrations (
    name TEXT PRIMARY KEY,
    checksum CHAR(64) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
  )`);
  const migrationDirectory = new URL('../server/migrations/', import.meta.url);
  const allMigrations = (await readdir(migrationDirectory)).filter(name => name.endsWith('.sql')).sort();
  const migrations = allMigrations.slice(0, 9);
  for (const name of migrations) {
    const sql = (await readFile(new URL(name, migrationDirectory), 'utf8')).replace(/\r\n/g, '\n');
    await database.exec(sql);
    await database.query('INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)', [name, createHash('sha256').update(sql).digest('hex')]);
  }

  const issuerId = randomUUID();
  const memberId = randomUUID();
  const roomId = randomUUID();
  const membershipId = randomUUID();
  const groupId = randomUUID();
  await database.query(`INSERT INTO sessions(id,token_hash,expires_at) VALUES
    ($1,$2,clock_timestamp()+interval '1 hour'),($3,$4,clock_timestamp()+interval '1 hour')`,
  [issuerId, '1'.repeat(64), memberId, '2'.repeat(64)]);
  await database.query(`INSERT INTO rooms(id,owner_id,join_code,title,status,expires_at)
    VALUES($1,$2,'UPGRADE01','Existing room','open',clock_timestamp()+interval '1 day')`, [roomId, issuerId]);
  await database.query(`INSERT INTO memberships(id,room_id,session_id,label,status,decided_at)
    VALUES($1,$2,$3,'Existing member','approved',clock_timestamp())`, [membershipId, roomId, memberId]);
  await database.query(`INSERT INTO credential_groups(id,owner_session_id,name)
    VALUES($1,$2,'Existing credential group')`, [groupId, issuerId]);

  const roomFileMigrations = allMigrations.slice(9, 12);
  for (const name of roomFileMigrations) {
    const sql = (await readFile(new URL(name, migrationDirectory), 'utf8')).replace(/\r\n/g, '\n');
    await database.exec(sql);
    await database.query('INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)', [name, createHash('sha256').update(sql).digest('hex')]);
  }
  const keyFingerprint = 'c'.repeat(64);
  const fileId = randomUUID();
  const descriptor = Buffer.from('existing encrypted descriptor');
  const ciphertext = Buffer.alloc(16, 0x44);
  await database.query('INSERT INTO room_file_keys(room_id,fingerprint) VALUES($1,$2)', [roomId, keyFingerprint]);
  await database.query(`INSERT INTO room_files(id,room_id,uploader_id,descriptor,chunk_count,encrypted_bytes)
    VALUES($1,$2,$3,$4,1,16)`, [fileId, roomId, memberId, descriptor]);
  await database.query('INSERT INTO room_file_chunks(file_id,chunk_index,ciphertext,sha256) VALUES($1,0,$2,$3)', [fileId, ciphertext, createHash('sha256').update(ciphertext).digest('hex')]);

  await migrate(database);

  const [room] = await database.query<{ title: string; status: string }>('SELECT title,status FROM rooms WHERE id=$1', [roomId]);
  const [membership] = await database.query<{ label: string; status: string }>('SELECT label,status FROM memberships WHERE id=$1', [membershipId]);
  const [group] = await database.query<{ name: string }>('SELECT name FROM credential_groups WHERE id=$1', [groupId]);
  const [fileKey] = await database.query<{ fingerprint: string; epoch: number; history_envelope: string | null }>('SELECT fingerprint,epoch,history_envelope FROM room_file_keys WHERE room_id=$1', [roomId]);
  const [file] = await database.query<{ descriptor: Buffer; key_fingerprint: string; status: string }>('SELECT descriptor,key_fingerprint,status FROM room_files WHERE id=$1', [fileId]);
  const [chunk] = await database.query<{ ciphertext: Buffer; sha256: string }>('SELECT ciphertext,sha256 FROM room_file_chunks WHERE file_id=$1 AND chunk_index=0', [fileId]);
  const migrationRows = await database.query<{ name: string }>('SELECT name FROM schema_migrations ORDER BY name');
  assert.deepEqual(room, { title: 'Existing room', status: 'open' });
  assert.deepEqual(membership, { label: 'Existing member', status: 'approved' });
  assert.equal(group.name, 'Existing credential group');
  assert.deepEqual(fileKey, { fingerprint: keyFingerprint, epoch: 1, history_envelope: null });
  assert.equal(file.key_fingerprint, keyFingerprint);
  assert.equal(file.status, 'uploading');
  assert.deepEqual(Buffer.from(file.descriptor), descriptor);
  assert.deepEqual(Buffer.from(chunk.ciphertext), ciphertext);
  assert.equal(chunk.sha256, createHash('sha256').update(ciphertext).digest('hex'));
  assert.deepEqual(migrationRows.map(({ name }) => name), allMigrations);
});
