import type { Store, Options } from 'express-rate-limit';
import type { Database } from './database.js';
// Atomic PostgreSQL windows coordinate budgets across all API instances.
export class DatabaseRateStore implements Store {
  windowMs = 60_000;
  localKeys = false;
  get prefix() { return this.namespace + ':'; }
  constructor(private database: Database, private namespace: string) {}
  init(options: Options) { this.windowMs = options.windowMs; }
  async increment(key: string) {
    const [row] = await this.database.query<{ hits: number; reset_at: Date }>(
      `INSERT INTO request_budgets(key, hits, reset_at) VALUES ($1, 1, clock_timestamp() + $2 * interval '1 millisecond')
       ON CONFLICT(key) DO UPDATE SET
         hits = CASE WHEN request_budgets.reset_at <= clock_timestamp() THEN 1 ELSE request_budgets.hits + 1 END,
         reset_at = CASE WHEN request_budgets.reset_at <= clock_timestamp() THEN EXCLUDED.reset_at ELSE request_budgets.reset_at END
       RETURNING hits, reset_at`, [this.namespace + ':' + key, this.windowMs]);
    return { totalHits: row.hits, resetTime: row.reset_at };
  }
  async decrement(key: string) { await this.database.query('UPDATE request_budgets SET hits = GREATEST(0, hits - 1) WHERE key = $1', [this.namespace + ':' + key]); }
  async resetKey(key: string) { await this.database.query('DELETE FROM request_budgets WHERE key = $1', [this.namespace + ':' + key]); }
}
