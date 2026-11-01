import type { Queries } from "./database.js";
import { requireCondition } from "./errors.js";

const ENTRY_FRESH_MS = 5 * 60 * 1000;

export async function requireRoomLocation(
  queries: Queries,
  roomId: string,
  sessionId: string,
) {
  const [room] = await queries.query<{ geo_lat: number | null }>(
    "SELECT geo_lat FROM rooms WHERE id = $1",
    [roomId],
  );
  requireCondition(room, 404, "ROOM_NOT_FOUND", "Room not found.");
  if (room.geo_lat == null) return;
  const [membership] = await queries.query<{
    last_inside: boolean | null;
    fresh: boolean;
  }>(
    `SELECT last_inside, last_checked_at >= clock_timestamp() - ($3 * interval '1 millisecond') AS fresh
     FROM memberships WHERE room_id = $1 AND session_id = $2`,
    [roomId, sessionId, ENTRY_FRESH_MS],
  );
  requireCondition(
    membership?.fresh,
    403,
    "GEO_STALE",
    "Share a fresh location to enter this room.",
  );
  requireCondition(
    membership.last_inside === true,
    403,
    "GEO_OUTSIDE",
    "You are outside this room’s area.",
  );
}
