import type { Database } from "./database.js";
import { recordActivity } from "./activity.js";
import { reclaimStaleUploads, STALE_UPLOAD_AGE } from "./staleUploads.js";

export interface CleanupCounts {
  roomsCompleted: number;
  submissionsDeleted: number;
  sharedFilesDeleted: number;
  staleUploadsDeleted: number;
  staleBytesReclaimed: number;
}

export async function runSubmissionCleanupPass(
  database: Database,
): Promise<CleanupCounts> {
  const counts: CleanupCounts = {
    roomsCompleted: 0,
    submissionsDeleted: 0,
    sharedFilesDeleted: 0,
    staleUploadsDeleted: 0,
    staleBytesReclaimed: 0,
  };
  const rooms = await database.query<{ id: string }>(
    `SELECT id FROM rooms WHERE submission_cleanup_enabled
     AND submissions_purged_at IS NULL AND expires_at <= clock_timestamp()
     ORDER BY expires_at, id LIMIT 50`,
  );

  for (const { id } of rooms) {
    await database.transaction(async (tx) => {
      await tx.query("SELECT id FROM rooms WHERE id = $1 FOR UPDATE", [id]);
      const [room] = await tx.query<{ eligible: boolean }>(
        `SELECT submission_cleanup_enabled AND submissions_purged_at IS NULL
         AND expires_at <= clock_timestamp() AS eligible FROM rooms WHERE id = $1`,
        [id],
      );
      if (!room?.eligible) return;
      const [deleted] = await tx.query<{ count: number }>(
        `WITH removed AS (
           DELETE FROM private_submissions WHERE room_id = $1 RETURNING id
         ) SELECT count(*)::int AS count FROM removed`,
        [id],
      );
      const [shared] = await tx.query<{ count: number }>(
        `WITH removed AS (DELETE FROM room_files WHERE room_id = $1 RETURNING id)
         SELECT count(*)::int AS count FROM removed`,
        [id],
      );
      const [updated] = await tx.query<{ id: string }>(
        `UPDATE rooms SET submissions_purged_at = clock_timestamp()
         WHERE id = $1 AND submissions_purged_at IS NULL RETURNING id`,
        [id],
      );
      if (!updated) return;
      await recordActivity(tx, id, "submissions_purged");
      counts.roomsCompleted++;
      counts.submissionsDeleted += deleted.count;
      counts.sharedFilesDeleted += shared.count;
    });
  }

  const stale = await database.query<{ id: string; room_id: string }>(
    `SELECT id, room_id FROM private_submissions
     WHERE status = 'uploading'
       AND created_at < ${STALE_UPLOAD_AGE}
     ORDER BY created_at, id LIMIT 100`,
  );
  for (const submission of stale) {
    await database.transaction(async (tx) => {
      await tx.query("SELECT id FROM rooms WHERE id = $1 FOR UPDATE", [
        submission.room_id,
      ]);
      const removed = await reclaimStaleUploads(
        tx,
        submission.room_id,
        1,
        submission.id,
      );
      counts.staleUploadsDeleted += removed.count;
      counts.staleBytesReclaimed += removed.bytes;
    });
  }
  const staleShared = await database.query<{ id: string; room_id: string }>(
    `SELECT id,room_id FROM room_files WHERE status='uploading'
     AND created_at < clock_timestamp()-interval '24 hours' ORDER BY created_at,id LIMIT 100`,
  );
  for (const file of staleShared) {
    await database.transaction(async (tx) => {
      await tx.query("SELECT id FROM rooms WHERE id=$1 FOR UPDATE", [
        file.room_id,
      ]);
      const removed = await tx.query<{ id: string }>(
        `DELETE FROM room_files WHERE id=$1 AND room_id=$2
        AND status='uploading' AND created_at < clock_timestamp()-interval '24 hours' RETURNING id`,
        [file.id, file.room_id],
      );
      counts.sharedFilesDeleted += removed.length;
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
        console.error("Submission cleanup pass failed", {
          name: error instanceof Error ? error.name : "UnknownError",
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
