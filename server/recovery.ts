import { createHash, randomBytes } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import type { Database } from './database.js';
import { roomId } from '../shared/rooms.js';
import { requireCondition } from './errors.js';
import { recordActivity } from './activity.js';
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
export function recoveryRoutes(database: Database) {
  const router = Router();
  router.post('/rooms/:id/recovery', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const token = randomBytes(32).toString('base64url');
    await database.transaction(async tx => {
      const [room] = await tx.query<{ owner_id: string }>('SELECT owner_id FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      requireCondition(room?.owner_id === request.session!.id, 403, 'OWNER_REQUIRED', 'Only the organizer can create a recovery code.');
      await tx.query(`INSERT INTO owner_recovery(room_id, token_hash) VALUES ($1, $2)
        ON CONFLICT(room_id) DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = clock_timestamp()`, [id, hash(token)]);
    });
    response.json({ recoveryCode: token });
  });
  router.post('/rooms/recover', async (request, response) => {
    const { recoveryCode } = z.object({ recoveryCode: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict().parse(request.body);
    const id = await database.transaction(async tx => {
      // Every ownership mutation locks the room first, including concurrent recoveries.
      const [candidate] = await tx.query<{ room_id: string }>('SELECT room_id FROM owner_recovery WHERE token_hash = $1', [hash(recoveryCode)]);
      requireCondition(candidate, 403, 'RECOVERY_INVALID', 'Recovery code is invalid or already used.');
      const [room] = await tx.query<{ owner_id: string }>('SELECT owner_id FROM rooms WHERE id = $1 FOR UPDATE', [candidate.room_id]);
      const used = await tx.query('DELETE FROM owner_recovery WHERE room_id = $1 AND token_hash = $2 RETURNING room_id', [candidate.room_id, hash(recoveryCode)]);
      requireCondition(used.length, 403, 'RECOVERY_INVALID', 'Recovery code is invalid or already used.');
      const next = request.session!.id;
      if (room.owner_id !== next) {
        await tx.query('DELETE FROM room_file_envelopes WHERE recipient_id = $2 AND file_id IN (SELECT id FROM room_files WHERE room_id = $1)', [candidate.room_id, next]);
        await tx.query('UPDATE room_file_envelopes SET recipient_id = $3 WHERE recipient_id = $2 AND file_id IN (SELECT id FROM room_files WHERE room_id = $1)', [candidate.room_id, room.owner_id, next]);
        await tx.query('UPDATE room_files SET owner_id = $2 WHERE room_id = $1', [candidate.room_id, next]);
        await tx.query('UPDATE rooms SET owner_id = $2 WHERE id = $1', [candidate.room_id, next]);
        await recordActivity(tx, candidate.room_id, 'ownership_recovered');
      }
      return candidate.room_id;
    });
    response.json({ roomId: id });
  });
  return router;
}
