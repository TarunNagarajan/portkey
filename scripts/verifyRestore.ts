import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { openDatabase } from '../server/database.js';
import { migrate } from '../server/migrations.js';
const container = process.env.POSTGRES_CONTAINER, base = process.env.TEST_DATABASE_URL;
if (!container || !base) throw new Error('Set POSTGRES_CONTAINER and TEST_DATABASE_URL.');
const suffix = randomBytes(6).toString('hex'), source = `portkey_backup_${suffix}`, target = `portkey_restore_${suffix}`;
const sql = (statement: string) => execFileSync('docker', ['exec', container, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', statement], { stdio: 'pipe' });
const connect = (name: string) => { const url = new URL(base); url.pathname = '/' + name; return openDatabase({ url: url.toString() }); };
sql(`CREATE DATABASE ${source}`); sql(`CREATE DATABASE ${target}`);
try {
  const database = await connect(source);
  try {
    await migrate(database);
    await database.exec(`CREATE TABLE restore_probe(id INTEGER PRIMARY KEY, ciphertext BYTEA);
      INSERT INTO restore_probe VALUES (1, decode(repeat('deadbeef',5),'hex'));`);
  } finally { await database.close(); }
  const archive = execFileSync('docker', ['exec', container, 'pg_dump', '-U', 'postgres', '-Fc', source], { maxBuffer: 64 * 1024 * 1024 });
  execFileSync('docker', ['exec', '-i', container, 'pg_restore', '-U', 'postgres', '--exit-on-error', '--no-owner', '-d', target], { input: archive });
  const restored = await connect(target);
  try {
    await migrate(restored);
    const [row] = await restored.query<{ ciphertext: string }>("SELECT encode(ciphertext,'hex') AS ciphertext FROM restore_probe");
    assert.equal(row.ciphertext, 'deadbeef'.repeat(5));
    const [tables] = await restored.query<{ count: number }>("SELECT count(*)::int AS count FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('rooms','room_files','room_file_chunks','room_file_envelopes','credential_challenges')");
    assert.equal(tables.count, 5);
  } finally { await restored.close(); }
  await mkdir('benchmark-results', { recursive: true });
  await writeFile('benchmark-results/restore.json', JSON.stringify({ archiveBytes: archive.length, schemaMigrationsVerified: true, appTablesRestored: 5, ciphertextBytesMatch: true, measuredAt: new Date().toISOString() }, null, 2));
  console.log('PostgreSQL backup/restore: migrations, application tables and ciphertext bytes verified.');
} finally { sql(`DROP DATABASE ${source}`); sql(`DROP DATABASE ${target}`); }
