import { createHash, timingSafeEqual } from 'node:crypto';
import { Router } from 'express';
import type { Database } from './database.js';
import { requireCondition } from './errors.js';
export function operationsRoutes(database: Database, token?: string) {
  const router = Router();
  const digest = (value: string) => createHash('sha256').update(value).digest();
  router.get('/ops/metrics', async (request, response) => {
    requireCondition(token, 404, 'NOT_FOUND', 'Metrics are disabled.');
    requireCondition(timingSafeEqual(digest(request.get('authorization') ?? ''), digest(`Bearer ${token}`)), 403, 'METRICS_AUTH_REQUIRED', 'Metrics authorization required.');
    const [metrics] = await database.query(`SELECT
      (SELECT count(*)::int FROM rooms WHERE expires_at <= clock_timestamp() AND files_purged_at IS NULL) AS cleanup_backlog,
      (SELECT count(*)::int FROM room_files WHERE status = 'uploading' AND created_at < clock_timestamp() - interval '24 hours') AS stale_uploads,
      (SELECT COALESCE(sum(encrypted_bytes), 0)::text FROM room_files) AS encrypted_bytes,
      (SELECT extract(epoch FROM clock_timestamp() - min(expires_at))::bigint FROM rooms WHERE expires_at <= clock_timestamp() AND files_purged_at IS NULL) AS oldest_cleanup_delay_seconds`);
    response.json(metrics);
  });
  return router;
}
