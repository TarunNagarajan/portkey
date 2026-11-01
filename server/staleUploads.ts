import type { Queries } from './database.js';

export const STALE_UPLOAD_AGE = "clock_timestamp() - interval '24 hours'";

export async function reclaimStaleFileUploads(
  queries: Queries,
  roomId: string,
  limit: number,
  fileId?: string,
): Promise<{ count: number; bytes: number }> {
  const candidates = await queries.query<{ id: string; encrypted_bytes: string }>(
    `SELECT id, encrypted_bytes::text AS encrypted_bytes FROM room_files
     WHERE room_id = $1 AND status = 'uploading'
       AND created_at < ${STALE_UPLOAD_AGE}
       AND ($2::uuid IS NULL OR id = $2)
     ORDER BY created_at, id LIMIT $3 FOR UPDATE`,
    [roomId, fileId ?? null, limit],
  );
  let count = 0;
  let bytes = 0;
  for (const row of candidates) {
    const [deleted] = await queries.query<{ encrypted_bytes: string }>(
      `DELETE FROM room_files WHERE id = $1 AND room_id = $2
       AND status = 'uploading' AND created_at < ${STALE_UPLOAD_AGE}
       RETURNING encrypted_bytes::text AS encrypted_bytes`,
      [row.id, roomId],
    );
    if (deleted) {
      count++;
      bytes += Number(deleted.encrypted_bytes);
    }
  }
  return { count, bytes };
}
