import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import type { Database } from './database.js';

export async function migrate(database: Database) {
  await database.transaction(async transaction => {
    await transaction.query('SELECT pg_advisory_xact_lock(742091)');
    await transaction.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY, checksum CHAR(64) NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
    )`);
    const directory = new URL('./migrations/', import.meta.url);
    const files = (await readdir(directory)).filter(name => name.endsWith('.sql')).sort();
    for (const name of files) {
      const sql = await readFile(new URL(name, directory), 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const [applied] = await transaction.query<{ checksum: string }>(
        'SELECT checksum FROM schema_migrations WHERE name = $1', [name]
      );
      if (applied && applied.checksum !== checksum) throw new Error(`Migration changed: ${name}`);
      if (applied) continue;
      await transaction.exec(sql);
      await transaction.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [name, checksum]);
    }
  });
}
