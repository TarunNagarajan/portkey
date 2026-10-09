import { PGlite } from '@electric-sql/pglite';
import { Pool, type PoolClient } from 'pg';
import { mkdir } from 'node:fs/promises';

export interface Queries {
  query<T>(sql: string, parameters?: unknown[]): Promise<T[]>;
  exec(sql: string): Promise<void>;
}

export interface Database extends Queries {
  transaction<T>(work: (queries: Queries) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

function postgresQueries(connection: Pool | PoolClient): Queries {
  return {
    async query<T>(sql: string, parameters: unknown[] = []) {
      return (await connection.query(sql, parameters)).rows as T[];
    },
    async exec(sql: string) { await connection.query(sql); }
  };
}

export async function openDatabase(options: { url?: string; dataDir?: string } = {}): Promise<Database> {
  if (options.url) {
    const pool = new Pool({ connectionString: options.url, max: 10 });
    return {
      ...postgresQueries(pool),
      async transaction<T>(work: (queries: Queries) => Promise<T>) {
        const connection = await pool.connect();
        try {
          await connection.query('BEGIN');
          const result = await work(postgresQueries(connection));
          await connection.query('COMMIT');
          return result;
        } catch (error) {
          await connection.query('ROLLBACK');
          throw error;
        } finally { connection.release(); }
      },
      close: () => pool.end()
    };
  }

  if (options.dataDir) await mkdir(options.dataDir, { recursive: true });
  const database = await PGlite.create(options.dataDir);
  return {
    async query<T>(sql: string, parameters: unknown[] = []) {
      return (await database.query<T>(sql, parameters)).rows;
    },
    async exec(sql: string) { await database.exec(sql); },
    transaction: work => database.transaction(transaction => work({
      async query<T>(sql: string, parameters: unknown[] = []) {
        return (await transaction.query<T>(sql, parameters)).rows;
      },
      async exec(sql: string) { await transaction.exec(sql); }
    })),
    close: () => database.close()
  };
}
