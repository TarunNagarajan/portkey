import { createHash, createPublicKey } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import type { Database, Queries } from './database.js';
import { requireCondition } from './errors.js';
import { recordActivity } from './activity.js';
import { requireParticipantAccess } from './participantAccess.js';
import { roomId } from '../shared/rooms.js';

const b64 = z
  .string()
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const fingerprint = (value: Buffer) =>
  createHash('sha256').update(value).digest('hex');
const validP256 = (value: Buffer) => {
  if (value.length !== 65 || value[0] !== 4) return false;
  try {
    createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: value.subarray(1, 33).toString('base64url'),
        y: value.subarray(33, 65).toString('base64url'),
      },
      format: 'jwk',
    });
    return true;
  } catch {
    return false;
  }
};

interface RoomPolicy {
  id: string;
  owner_id: string;
  status: string;
  expires_at: Date;
  is_expired: boolean;
  label?: string;
}

// Refresh the deadline at the point this policy is checked. Transactional
// mutation callers invoke this after acquiring the room lock.
async function refreshPolicy(
  queries: Queries,
  room: RoomPolicy,
  message: string,
) {
  const [fresh] = await queries.query<{ expired: boolean; status: string }>(
    'SELECT expires_at <= clock_timestamp() AS expired, status FROM rooms WHERE id = $1',
    [room.id],
  );
  room.status = fresh.status;
  room.is_expired = fresh.expired;
  requireCondition(
    room.status === 'open' && !room.is_expired,
    410,
    'ROOM_CLOSED',
    message,
  );
}

function requireRoomOwner(room: RoomPolicy, sessionId: string) {
  requireCondition(
    room.owner_id === sessionId,
    403,
    'OWNER_REQUIRED',
    'Only the organizer can register this room’s encryption key.',
  );
}

async function requireParticipant(
  queries: Queries,
  room: RoomPolicy,
  sessionId: string,
) {
  await refreshPolicy(
    queries,
    room,
    'This room no longer registers participant keys.',
  );
  requireCondition(
    room.owner_id !== sessionId,
    403,
    'OWNER_REQUIRED',
    'The organizer registers their key through the owner endpoint.',
  );
  const membership = await requireParticipantAccess(queries, room.id, sessionId);
  room.label = membership.label;
}

export function keyRoutes(database: Database) {
  const router = Router();

  router.post('/rooms/:id/keys/owner', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ publicKey: b64 }).strict().parse(request.body);
    const publicKey = Buffer.from(input.publicKey, 'base64');
    requireCondition(
      validP256(publicKey),
      422,
      'INVALID_KEY',
      'Organizer key is invalid.',
    );
    const digest = await database.transaction(async (transaction) => {
      const [room] = await transaction.query<RoomPolicy>(
        'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
        [id],
      );
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      requireRoomOwner(room, request.session!.id);
      requireCondition(
        room.status !== 'closed' && !room.is_expired,
        410,
        'ROOM_CLOSED',
        'This room has closed.',
      );
      const value = fingerprint(publicKey);
      const existing = await transaction.query<{ fingerprint: string }>(
        'SELECT fingerprint FROM room_recipient_keys WHERE room_id = $1',
        [id],
      );
      requireCondition(
        !existing.length || existing[0].fingerprint === value,
        409,
        'KEY_IMMUTABLE',
        'The organizer key is already registered and cannot be replaced.',
      );
      if (!existing.length) {
        await transaction.query(
          'INSERT INTO room_recipient_keys (room_id, public_key, fingerprint) VALUES ($1, $2, $3)',
          [id, publicKey, value],
        );
        await recordActivity(transaction, id, 'key_registered');
      }
      return value;
    });
    response.status(201).json({ fingerprint: digest });
  });

  router.post('/rooms/:id/keys/room-access', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ publicKey: b64 }).strict().parse(request.body);
    const publicKey = Buffer.from(input.publicKey, 'base64');
    requireCondition(validP256(publicKey), 422, 'INVALID_KEY', 'Room access key is invalid.');
    const value = fingerprint(publicKey);
    await database.transaction(async tx => {
      const [room] = await tx.query<RoomPolicy>('SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      requireRoomOwner(room, request.session!.id);
      requireCondition(room.status !== 'closed' && !room.is_expired, 410, 'ROOM_CLOSED', 'This room has closed.');
      const [existing] = await tx.query<{ fingerprint: string }>('SELECT fingerprint FROM room_access_keys WHERE room_id = $1', [id]);
      requireCondition(!existing || existing.fingerprint === value, 409, 'KEY_IMMUTABLE', 'Restore the registered room access key from the latest backup.');
      if (!existing) await tx.query('INSERT INTO room_access_keys(room_id, public_key, fingerprint) VALUES ($1, $2, $3)', [id, publicKey, value]);
    });
    response.status(201).json({ fingerprint: value });
  });

  router.post('/rooms/:id/keys/participant', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ publicKey: b64 }).strict().parse(request.body);
    const publicKey = Buffer.from(input.publicKey, 'base64');
    requireCondition(
      validP256(publicKey),
      422,
      'INVALID_KEY',
      'Browser key is invalid.',
    );
    const digest = await database.transaction(async (transaction) => {
      const [room] = await transaction.query<RoomPolicy>(
        'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
        [id],
      );
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      await requireParticipant(transaction, room, request.session!.id);
      const value = fingerprint(publicKey);
      const existing = await transaction.query<{ fingerprint: string }>(
        'SELECT fingerprint FROM session_recipient_keys WHERE room_id = $1 AND session_id = $2',
        [id, request.session!.id],
      );
      requireCondition(
        !existing.length || existing[0].fingerprint === value,
        409,
        'KEY_IMMUTABLE',
        'This browser key is already registered for the room.',
      );
      if (!existing.length) {
        await transaction.query(
          'INSERT INTO session_recipient_keys (room_id, session_id, public_key, fingerprint) VALUES ($1, $2, $3, $4)',
          [id, request.session!.id, publicKey, value],
        );
        await recordActivity(transaction, id, 'key_registered');
      }
      return value;
    });
    response.status(201).json({ fingerprint: digest });
  });

  router.post('/rooms/:id/keys/rotate', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ publicKey: b64, expectedFingerprint: z.string().regex(/^[a-f0-9]{64}$/),
      envelopes: z.array(z.object({ fileId: roomId, enc: b64, ciphertext: b64 }).strict()).max(1000),
    }).strict().parse(request.body);
    const publicKey = Buffer.from(input.publicKey, 'base64');
    requireCondition(validP256(publicKey), 422, 'INVALID_KEY', 'The replacement key is invalid.');
    const value = fingerprint(publicKey);
    await database.transaction(async tx => {
      const [room] = await tx.query<RoomPolicy>('SELECT id, owner_id, status, expires_at FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      await refreshPolicy(tx, room, 'This room no longer rotates keys.');
      const owner = room.owner_id === request.session!.id;
      if (!owner) await requireParticipant(tx, room, request.session!.id);
      const table = owner ? 'room_recipient_keys' : 'session_recipient_keys';
      const predicate = owner ? 'room_id = $1' : 'room_id = $1 AND session_id = $2';
      const params = owner ? [id] : [id, request.session!.id];
      const [current] = await tx.query<{ fingerprint: string }>(`SELECT fingerprint FROM ${table} WHERE ${predicate}`, params);
      requireCondition(current?.fingerprint === input.expectedFingerprint, 409, 'KEY_CHANGED', 'Refresh the registered key before rotating.');
      const pending = await tx.query("SELECT 1 FROM room_files WHERE room_id = $1 AND status = 'uploading' LIMIT 1", [id]);
      requireCondition(!pending.length, 409, 'UPLOADS_PENDING', 'Finish or discard pending uploads before rotating keys.');
      const files = await tx.query<{ id: string }>(`SELECT f.id FROM room_files f JOIN room_file_envelopes e ON e.file_id = f.id
        WHERE f.room_id = $1 AND e.recipient_id = $2 AND f.status = 'complete'`, [id, request.session!.id]);
      requireCondition(new Set(input.envelopes.map(e => e.fileId)).size === files.length && input.envelopes.length === files.length && files.every(f => input.envelopes.some(e => e.fileId === f.id)), 422, 'ENVELOPES_REQUIRED', 'Rewrap every existing file key before rotation.');
      for (const envelope of input.envelopes) {
        const enc = Buffer.from(envelope.enc, 'base64'), ciphertext = Buffer.from(envelope.ciphertext, 'base64');
        requireCondition(enc.length === 65 && ciphertext.length === 48, 422, 'INVALID_ENCRYPTION', 'Replacement envelope is invalid.');
        await tx.query('UPDATE room_file_envelopes SET enc = $3, ciphertext = $4 WHERE file_id = $1 AND recipient_id = $2', [envelope.fileId, request.session!.id, enc, ciphertext]);
      }
      await tx.query(`UPDATE ${table} SET public_key = $${params.length+1}, fingerprint = $${params.length+2} WHERE ${predicate}`, [...params, publicKey, value]);
      await recordActivity(tx, id, 'key_rotated');
    });
    response.json({ fingerprint: value });
  });

  return router;
}
