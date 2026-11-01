import { Router } from 'express';
import { z } from 'zod';
import type { Database } from './database.js';
import { requireCondition } from './errors.js';
import { recordActivity } from './activity.js';
import { roomId } from '../shared/rooms.js';
import { verifyRevocation } from '../scripts/issuerLib.js';
const field = z.string().regex(/^[0-9]{1,77}$/);
export function issuerRoutes(database: Database) {
  const router = Router();
  // A revocation is authorized by the pinned issuer signature, not a browser cookie.
  router.post('/issuer/revocations', async (request, response) => {
    const input = z.object({ roomId, nullifier: field, signature: z.object({ R8x: field, R8y: field, S: field }).strict() }).strict().parse(request.body);
    await database.transaction(async tx => {
      const [room] = await tx.query<{ credential_issuer_ax: string; credential_issuer_ay: string }>('SELECT credential_issuer_ax, credential_issuer_ay FROM rooms WHERE id = $1 FOR UPDATE', [input.roomId]);
      requireCondition(room?.credential_issuer_ax && verifyRevocation({ ax: room.credential_issuer_ax, ay: room.credential_issuer_ay }, input.roomId, input.nullifier, input.signature), 403, 'ISSUER_SIGNATURE_REQUIRED', 'A signature from this room’s credential issuer is required.');
      await tx.query('INSERT INTO credential_revocations(room_id, nullifier) VALUES ($1, $2) ON CONFLICT DO NOTHING', [input.roomId, input.nullifier]);
      const members = await tx.query<{ label: string }>("UPDATE memberships SET status = 'revoked', decided_at = clock_timestamp() WHERE room_id = $1 AND credential_nullifier = $2 AND status = 'approved' RETURNING label", [input.roomId, input.nullifier]);
      for (const member of members) await recordActivity(tx, input.roomId, 'member_revoked', member.label);
    });
    response.status(204).end();
  });
  return router;
}
