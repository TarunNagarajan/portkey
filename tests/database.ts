import { randomBytes } from 'node:crypto';
import { Pool } from 'pg';
import { openDatabase as open, type Database } from '../server/database.js';
export type { Database } from '../server/database.js';
export async function openDatabase(options: Parameters<typeof open>[0] = {}): Promise<Database> {
  const url = process.env.TEST_DATABASE_URL;
  if (!url || options.url || options.dataDir) return open(options);
  const admin = new Pool({ connectionString: url });
  const schema = `portkey_test_${randomBytes(12).toString('hex')}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const connection = new URL(url);
  connection.searchParams.set('options', `-c search_path=${schema}`);
  const database = await open({ url: connection.toString() });
  return { ...database, async close() {
    await database.close();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end();
  } };
}
