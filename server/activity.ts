import { z } from 'zod';
import type { ActivityEvent, ActivityKind, ActivityPage, RoomField } from '../shared/activity.js';
import type { Queries } from './database.js';

export const activityQuery = z
  .object({
    before: z
      .string()
      .regex(/^[1-9]\d*$/)
      .max(19)
      .refine((value) => /^\d{1,19}$/.test(value) && BigInt(value) <= 9223372036854775807n)
      .optional(),
  })
  .strict();

export async function recordActivity(
  queries: Queries,
  roomId: string,
  kind: ActivityKind,
  memberLabel: string | null = null,
  changedFields: RoomField[] = [],
) {
  await queries.query(
    'INSERT INTO room_activity (room_id, kind, member_label, changed_fields) VALUES ($1, $2, $3, $4)',
    [roomId, kind, memberLabel, changedFields],
  );
}

export async function readActivity(
  queries: Queries,
  roomId: string,
  before?: string,
): Promise<ActivityPage> {
  const rows = await queries.query<Omit<ActivityEvent, 'createdAt'> & { createdAt: Date }>(
    `SELECT a.id::text AS id, a.kind, a.member_label AS "memberLabel", a.changed_fields AS "changedFields",
     a.created_at AS "createdAt" FROM room_activity a
     WHERE a.room_id = $1 AND ($2::bigint IS NULL OR a.id < $2::bigint)
     ORDER BY a.id DESC LIMIT 21`,
    [roomId, before ?? null],
  );
  const events = rows
    .slice(0, 20)
    .map((row) => ({ ...row, createdAt: row.createdAt.toISOString() }));
  return { events, nextCursor: rows.length > 20 ? events.at(-1)!.id : null };
}
