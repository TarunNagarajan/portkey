import type { Queries } from './database.js';
import { requireCondition } from './errors.js';

// All participant entry points share the same database-clock location policy.
export async function requireParticipantAccess(queries: Queries, roomId: string, sessionId: string) {
  const [member] = await queries.query<{
    status: string; label: string; geo_required: boolean;
    fresh: boolean; credential_active: boolean; last_inside: boolean | null;
  }>(
    `SELECT m.status, m.label,
       (m.credential_expires_at IS NULL OR m.credential_expires_at > clock_timestamp())
       AND NOT EXISTS (SELECT 1 FROM credential_revocations v WHERE v.room_id = m.room_id AND v.nullifier = m.credential_nullifier) AS credential_active, r.geo_lat IS NOT NULL AS geo_required,
       m.last_checked_at BETWEEN clock_timestamp() - interval '5 minutes'
         AND clock_timestamp() AS fresh, m.last_inside
     FROM memberships m JOIN rooms r ON r.id = m.room_id
     JOIN sessions s ON s.id = m.session_id AND s.expires_at > clock_timestamp()
     WHERE m.room_id = $1 AND m.session_id = $2`,
    [roomId, sessionId],
  );
  requireCondition(member?.status === 'approved', 403, 'ADMISSION_REQUIRED', 'Organizer approval is required.');
  requireCondition(member.credential_active, 403, 'CREDENTIAL_INACTIVE', 'Your credential expired or was revoked.');
  if (member.geo_required) {
    requireCondition(member.fresh === true, 403, 'GEO_STALE', 'Share a fresh location to enter this room.');
    requireCondition(member.last_inside === true, 403, 'GEO_OUTSIDE', 'You are outside this room’s area.');
  }
  return member;
}
