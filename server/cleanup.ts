import type { Database } from './database.js';
import { recordActivity } from './activity.js';
import { reclaimStaleFileUploads, STALE_UPLOAD_AGE } from './staleUploads.js';

export interface CleanupCounts {
  roomsCompleted: number;
  filesDeleted: number;
  staleUploadsDeleted: number;
  staleBytesReclaimed: number;
}

export async function runFileCleanupPass(database: Database): Promise<CleanupCounts> {
  const counts: CleanupCounts = {
    roomsCompleted: 0,
    filesDeleted: 0,
    staleUploadsDeleted: 0,
    staleBytesReclaimed: 0,
  };
  await database.query("DELETE FROM request_budgets WHERE reset_at < clock_timestamp() - interval '1 day'");
  await database.query('DELETE FROM credential_challenges WHERE expires_at < clock_timestamp()');
  // Keep proximity coordinates for at most one day, independently of room expiry.
  await database.query("UPDATE memberships SET last_lat = NULL, last_lng = NULL, last_accuracy_m = NULL, last_distance_m = NULL, last_inside = NULL, last_checked_at = NULL WHERE last_checked_at < clock_timestamp() - interval '1 day'");
  const rooms = await database.query<{ id: string }>(
    `SELECT id FROM rooms WHERE files_purged_at IS NULL
     AND expires_at <= clock_timestamp()
     ORDER BY expires_at, id LIMIT 50`,
  );

  for (const { id } of rooms) {
    await database.transaction(async (tx) => {
      await tx.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      const [room] = await tx.query<{ eligible: boolean }>(
        `SELECT files_purged_at IS NULL
         AND expires_at <= clock_timestamp() AS eligible FROM rooms WHERE id = $1`,
        [id],
      );
      if (!room?.eligible) return;
      const [deleted] = await tx.query<{ count: number }>(
        `WITH removed AS (
           DELETE FROM room_files WHERE room_id = $1 RETURNING id
         ) SELECT count(*)::int AS count FROM removed`,
        [id],
      );
      const [updated] = await tx.query<{ id: string }>(
        `UPDATE rooms SET files_purged_at = clock_timestamp()
         WHERE id = $1 AND files_purged_at IS NULL RETURNING id`,
        [id],
      );
      if (!updated) return;
      await recordActivity(tx, id, 'files_purged');
      counts.roomsCompleted++;
      counts.filesDeleted += deleted.count;
    });
  }

  const staleFiles = await database.query<{ id: string; room_id: string }>(
    `SELECT id, room_id FROM room_files
     WHERE status = 'uploading'
       AND created_at < ${STALE_UPLOAD_AGE}
     ORDER BY created_at, id LIMIT 100`,
  );
  for (const file of staleFiles) {
    await database.transaction(async (tx) => {
      await tx.query('SELECT id FROM rooms WHERE id = $1 FOR UPDATE', [file.room_id]);
      const removed = await reclaimStaleFileUploads(tx, file.room_id, 1, file.id);
      counts.staleUploadsDeleted += removed.count;
      counts.staleBytesReclaimed += removed.bytes;
    });
  }
  return counts;
}

export function startCleanupScheduler(
  work: () => Promise<unknown>,
  options: {
    intervalMs?: number;
    setTimer?: typeof setTimeout;
    clearTimer?: typeof clearTimeout;
  } = {},
) {
  const intervalMs = options.intervalMs ?? 60_000;
  const schedule = options.setTimer ?? setTimeout;
  const unschedule = options.clearTimer ?? clearTimeout;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let active: Promise<void> | undefined;
  let stopped = false;

  const run = () => {
    if (stopped || active) return;
    active = work()
      .then(() => undefined)
      .catch((error: unknown) => {
        console.error('File cleanup pass failed', {
          name: error instanceof Error ? error.name : 'UnknownError',
        });
      })
      .finally(() => {
        active = undefined;
        if (!stopped) timer = schedule(run, intervalMs);
      });
  };
  run();
  return {
    async stop() {
      stopped = true;
      if (timer) unschedule(timer);
      await active;
    },
  };
}
