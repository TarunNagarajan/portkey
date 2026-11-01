import { createHash } from 'node:crypto';
import express from 'express';
import { Router } from 'express';
import { z } from 'zod';
import type { Database, Queries } from './database.js';
import { requireCondition } from './errors.js';
import { recordActivity } from './activity.js';
import { roomId } from '../shared/rooms.js';
import { requireParticipantAccess } from './participantAccess.js';
import { reclaimStaleFileUploads } from './staleUploads.js';

const MAX_ROOM_BYTES = 5 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES = 250 * 1024 * 1024;
const MAX_CHUNKS = 250;
const CHUNK_BYTES = 1024 * 1024;
const MAX_RECIPIENTS = 1000;
const b64 = z
  .string()
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const fingerprint = (value: Buffer) =>
  createHash('sha256').update(value).digest('hex');

interface RoomPolicy {
  id: string;
  owner_id: string;
  status: string;
  expires_at: Date;
  is_expired: boolean;
}

async function roomPolicy(queries: Queries, id: string) {
  const [room] = await queries.query<RoomPolicy>(
    'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1',
    [id],
  );
  requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
  requireCondition(
    room.status === 'open' && !room.is_expired,
    410,
    'ROOM_CLOSED',
    'This room is no longer exchanging files.',
  );
  return room;
}

// Refresh the deadline at the point this policy is checked. Transactional
// mutation callers invoke this after acquiring the room lock.
async function refreshPolicy(queries: Queries, room: RoomPolicy) {
  const [fresh] = await queries.query<{ expired: boolean; status: string }>(
    'SELECT expires_at <= clock_timestamp() AS expired, status FROM rooms WHERE id = $1',
    [room.id],
  );
  room.status = fresh.status;
  room.is_expired = fresh.expired;
}

async function requireOwner(
  queries: Queries,
  room: RoomPolicy,
  sessionId: string,
) {
  await refreshPolicy(queries, room);
  requireCondition(
    room.status === 'open' && !room.is_expired,
    410,
    'ROOM_CLOSED',
    'This room is no longer exchanging files.',
  );
  requireCondition(
    room.owner_id === sessionId,
    403,
    'OWNER_REQUIRED',
    'Only the organizer can publish files.',
  );
}

async function requireVisible(
  queries: Queries,
  room: RoomPolicy,
  sessionId: string,
) {
  if (room.owner_id === sessionId) return 'owner';
  await requireParticipantAccess(queries, room.id, sessionId);
  return 'recipient';
}

async function eligibleRecipients(
  queries: Queries,
  room: RoomPolicy,
): Promise<Set<string>> {
  const rows = await queries.query<{ session_id: string }>(
    `SELECT m.session_id FROM memberships m JOIN sessions s ON s.id = m.session_id
     WHERE m.room_id = $1 AND m.status = 'approved' AND s.expires_at > clock_timestamp()`,
    [room.id],
  );
  return new Set([room.owner_id, ...rows.map((row) => row.session_id)]);
}

export function roomFileRoutes(database: Database) {
  const router = Router();
  router.use(
    '/rooms/:roomId/files/:fileId/chunks/:index',
    (request, response, next) => {
      if (request.method !== 'PUT') return next();
      void (async () => {
        const pathRoom = roomId.parse(request.params.roomId);
        const fileId = roomId.parse(request.params.fileId);
        const [room] = await database.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1',
          [pathRoom],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireOwner(database, room, request.session!.id);
        const [file] = await database.query<{
          owner_id: string;
          status: string;
          encrypted_descriptor: Buffer | null;
        }>(
          'SELECT owner_id, status, encrypted_descriptor FROM room_files WHERE id = $1 AND room_id = $2',
          [fileId, pathRoom],
        );
        requireCondition(
          file && file.owner_id === request.session!.id,
          404,
          'FILE_NOT_FOUND',
          'File not found.',
        );
        requireCondition(
          file.status === 'uploading' && file.encrypted_descriptor,
          409,
          'UPLOAD_UNAVAILABLE',
          'This file is no longer accepting chunks.',
        );
        express.raw({
          type: 'application/octet-stream',
          limit: CHUNK_BYTES + 16,
        })(request, response, next);
      })().catch(next);
    },
  );

  router.get('/rooms/:id/files/keys', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [room] = await database.query<RoomPolicy>(
      'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1',
      [id],
    );
    requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    if (room.owner_id !== request.session!.id) {
      requireCondition(
        room.status === 'open' && !room.is_expired,
        410,
        'ROOM_CLOSED',
        'This room is no longer exchanging files.',
      );
      await requireVisible(database, room, request.session!.id);
    } else
      requireCondition(
        room.status !== 'closed' && !room.is_expired,
        410,
        'ROOM_CLOSED',
        'This room has closed.',
      );
    const [ownerKey] = await database.query<{
      publicKey: Buffer;
      fingerprint: string;
    }>(
      'SELECT public_key AS "publicKey", fingerprint FROM room_recipient_keys WHERE room_id = $1',
      [id],
    );
    requireCondition(
      ownerKey,
      409,
      'KEYS_NOT_READY',
      'The organizer has not set up encryption for this room yet.',
    );
    const [recipientKey] = await database.query<{ fingerprint: string }>(
      'SELECT fingerprint FROM session_recipient_keys WHERE room_id = $1 AND session_id = $2',
      [id, request.session!.id],
    );
    const [roomAccess] = await database.query<{ public_key: Buffer; fingerprint: string }>('SELECT public_key, fingerprint FROM room_access_keys WHERE room_id = $1', [id]);
    const sharedKeyInfo = {
      roomAccessPublicKey: roomAccess ? Buffer.from(roomAccess.public_key).toString('base64') : null,
      roomAccessFingerprint: roomAccess?.fingerprint ?? null,
    };
    if (room.owner_id !== request.session!.id) {
      response.json({
        ownerPublicKey: Buffer.from(ownerKey.publicKey).toString('base64'),
        ownerFingerprint: ownerKey.fingerprint,
        recipientFingerprint: recipientKey?.fingerprint ?? null,
        ...sharedKeyInfo,
      });
      return;
    }
    const recipients = await database.query<{
      id: string;
      label: string;
      publicKey: Buffer;
      fingerprint: string;
    }>(
      `SELECT m.session_id AS id, m.label, k.public_key AS "publicKey", k.fingerprint
       FROM memberships m
       JOIN sessions s ON s.id = m.session_id AND s.expires_at > clock_timestamp()
       JOIN session_recipient_keys k ON k.room_id = m.room_id AND k.session_id = m.session_id
       WHERE m.room_id = $1 AND m.status = 'approved'
       ORDER BY m.label, m.session_id`,
      [id],
    );
    response.json({
      ownerPublicKey: Buffer.from(ownerKey.publicKey).toString('base64'),
      ownerFingerprint: ownerKey.fingerprint,
      ownerRecipientId: room.owner_id,
      ...sharedKeyInfo,
      recipients: recipients.map((row) => ({
        id: row.id,
        label: row.label,
        publicKey: Buffer.from(row.publicKey).toString('base64'),
        fingerprint: row.fingerprint,
      })),
    });
  });

  router.post('/rooms/:id/files', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { fileId: fileIdValue } = z
      .object({ fileId: roomId })
      .strict()
      .parse(request.body);
    let completed = false;
    let completionReceipt: unknown;
    await database.transaction(async (transaction) => {
      const [room] = await transaction.query<RoomPolicy>(
        'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
        [id],
      );
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      await requireOwner(transaction, room, request.session!.id);
      const [ownerKey] = await transaction.query<{ public_key: Buffer }>(
        'SELECT public_key FROM room_recipient_keys WHERE room_id = $1',
        [id],
      );
      requireCondition(
        ownerKey,
        409,
        'KEYS_REQUIRED',
        'The organizer must register their room key before publishing files.',
      );
      const [existing] = await transaction.query<{
        owner_id: string;
        status: string;
        room_id: string;
        receipt: unknown;
      }>(
        'SELECT owner_id, status, room_id, receipt FROM room_files WHERE id = $1 FOR UPDATE',
        [fileIdValue],
      );
      if (existing) {
        requireCondition(
          existing.room_id === id && existing.owner_id === request.session!.id,
          409,
          'UPLOAD_ID_CONFLICT',
          'This upload reference is already in use.',
        );
        completed = existing.status === 'complete';
        if (completed) completionReceipt = existing.receipt;
        return;
      }
      await reclaimStaleFileUploads(transaction, id, 1000);
      const [usage] = await transaction.query<{ total: string }>(
        `SELECT COALESCE(SUM(encrypted_bytes), 0)::text AS total FROM room_files WHERE room_id = $1`,
        [id],
      );
      requireCondition(
        Number(usage.total) < MAX_ROOM_BYTES,
        413,
        'ROOM_QUOTA',
        'The room has reached its encrypted storage limit.',
      );
      const [objectCount] = await transaction.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM room_files WHERE room_id = $1',
        [id],
      );
      requireCondition(
        objectCount.count < 1000,
        413,
        'OBJECT_LIMIT',
        'The room has reached its 1,000-file limit.',
      );
      const [pending] = await transaction.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM room_files WHERE room_id = $1 AND status = 'uploading'",
        [id],
      );
      requireCondition(
        pending.count < 20,
        429,
        'UPLOADS_PENDING',
        'Finish or retry the existing file uploads before starting another.',
      );
      const inserted = await transaction.query(
        'INSERT INTO room_files (id, room_id, owner_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING RETURNING id',
        [fileIdValue, id, request.session!.id],
      );
      requireCondition(
        inserted.length,
        409,
        'UPLOAD_ID_CONFLICT',
        'This upload reference is already in use.',
      );
    });
    response.status(201).json({
      id: fileIdValue,
      complete: completed,
      ...(completed ? { receipt: completionReceipt } : {}),
      chunkBytes: CHUNK_BYTES,
      maxFileBytes: MAX_FILE_BYTES,
    });
  });

  router.put(
    '/rooms/:roomId/files/:fileId/metadata',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const fileIdValue = roomId.parse(request.params.fileId);
      const input = z
        .object({
          descriptor: b64,
          roomEnvelope: z.object({ fingerprint: z.string().regex(/^[a-f0-9]{64}$/), enc: b64, ciphertext: b64 }).strict().optional(),
          recipientFingerprints: z.record(roomId, z.string().regex(/^[a-f0-9]{64}$/)).optional(),
          envelopes: z
            .array(
              z
                .object({
                  recipientId: roomId,
                  enc: b64,
                  ciphertext: b64,
                })
                .strict(),
            )
            .min(1)
            .max(MAX_RECIPIENTS),
        })
        .strict()
        .parse(request.body);
      const descriptor = Buffer.from(input.descriptor, 'base64');
      const envelopes = input.envelopes.map((envelope) => ({
        recipientId: envelope.recipientId,
        enc: Buffer.from(envelope.enc, 'base64'),
        ciphertext: Buffer.from(envelope.ciphertext, 'base64'),
      }));
      requireCondition(
        new Set(envelopes.map((x) => x.recipientId)).size === envelopes.length,
        422,
        'INVALID_ENCRYPTION',
        'Each recipient may appear only once.',
      );
      requireCondition(
        descriptor.length >= 69 &&
          descriptor.length <= 16_384 &&
          envelopes.every(
            (x) =>
              x.enc.length === 65 &&
              x.ciphertext.length >= 16 &&
              x.ciphertext.length <= 4096,
          ),
        422,
        'INVALID_ENCRYPTION',
        'Encrypted file metadata is invalid.',
      );
      await database.transaction(async (transaction) => {
        const [room] = await transaction.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
          [roomIdValue],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireOwner(transaction, room, request.session!.id);
        const [file] = await transaction.query<{
          owner_id: string;
          status: string;
          encrypted_descriptor: Buffer | null;
        }>(
          'SELECT owner_id, status, encrypted_descriptor FROM room_files WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [fileIdValue, roomIdValue],
        );
        requireCondition(
          file && file.owner_id === request.session!.id,
          404,
          'FILE_NOT_FOUND',
          'File not found.',
        );
        requireCondition(
          file.status === 'uploading',
          409,
          'UPLOAD_COMPLETE',
          'This upload has already completed.',
        );
        const [accessKey] = await transaction.query<{ fingerprint: string }>('SELECT fingerprint FROM room_access_keys WHERE room_id = $1', [roomIdValue]);
        const roomEnvelope = input.roomEnvelope;
        requireCondition(!accessKey || roomEnvelope, 409, 'ROOM_ACCESS_REQUIRED', 'Reload the organizer page before publishing so all room members receive access.');
        if (roomEnvelope) {
          requireCondition(accessKey?.fingerprint === roomEnvelope.fingerprint && Buffer.from(roomEnvelope.enc, 'base64').length === 65 && Buffer.from(roomEnvelope.ciphertext, 'base64').length === 48,
            422, 'INVALID_ENCRYPTION', 'Room-wide file envelope does not match this room.');
        }
        const eligible = await eligibleRecipients(transaction, room);
        if (input.recipientFingerprints) {
          const keys = await transaction.query<{ id: string; fingerprint: string }>(
            `SELECT r.owner_id AS id, k.fingerprint FROM rooms r JOIN room_recipient_keys k ON k.room_id = r.id WHERE r.id = $1
             UNION ALL SELECT session_id AS id, fingerprint FROM session_recipient_keys WHERE room_id = $1`, [roomIdValue]);
          requireCondition(envelopes.every(envelope => keys.some(key => key.id === envelope.recipientId && key.fingerprint === input.recipientFingerprints![key.id])),
            409, 'RECIPIENT_CHANGED', 'Recipient keys changed. Discard the saved plan and seal a fresh upload.');
        }

        requireCondition(
          envelopes.every((x) => eligible.has(x.recipientId)),
          422,
          'INVALID_RECIPIENT',
          'Only the organizer and approved participants can receive a file.',
        );
        requireCondition(
          envelopes.some((x) => x.recipientId === room.owner_id),
          422,
          'INVALID_RECIPIENT',
          'The organizer must keep a copy of the file key.',
        );
        if (file.encrypted_descriptor) {
          const stored = await transaction.query<{
            recipient_id: string;
            enc: Buffer;
            ciphertext: Buffer;
          }>(
            'SELECT recipient_id, enc, ciphertext FROM room_file_envelopes WHERE file_id = $1',
            [fileIdValue],
          );
          const [storedShared] = await transaction.query<{ fingerprint: string; enc: Buffer; ciphertext: Buffer }>('SELECT fingerprint, enc, ciphertext FROM room_file_shared_envelopes WHERE file_id = $1', [fileIdValue]);
          requireCondition(!storedShared ? !roomEnvelope : roomEnvelope && storedShared.fingerprint === roomEnvelope.fingerprint && Buffer.from(storedShared.enc).equals(Buffer.from(roomEnvelope.enc, 'base64')) && Buffer.from(storedShared.ciphertext).equals(Buffer.from(roomEnvelope.ciphertext, 'base64')),
            409, 'METADATA_CONFLICT', 'A retry must send the original room envelope.');
          const identical =
            Buffer.from(file.encrypted_descriptor).equals(descriptor) &&
            stored.length === envelopes.length &&
            envelopes.every((envelope) => {
              const match = stored.find(
                (row) => row.recipient_id === envelope.recipientId,
              );
              return (
                match &&
                Buffer.from(match.enc).equals(envelope.enc) &&
                Buffer.from(match.ciphertext).equals(envelope.ciphertext)
              );
            });
          requireCondition(
            identical,
            409,
            'METADATA_CONFLICT',
            'A retry must send the original encrypted metadata and envelopes.',
          );
          return;
        }
        await transaction.query(
          'UPDATE room_files SET encrypted_descriptor = $2 WHERE id = $1',
          [fileIdValue, descriptor],
        );
        if (roomEnvelope) await transaction.query('INSERT INTO room_file_shared_envelopes(file_id, fingerprint, enc, ciphertext) VALUES ($1, $2, $3, $4)', [fileIdValue, roomEnvelope.fingerprint, Buffer.from(roomEnvelope.enc, 'base64'), Buffer.from(roomEnvelope.ciphertext, 'base64')]);
        for (const envelope of envelopes)
          await transaction.query(
            'INSERT INTO room_file_envelopes (file_id, recipient_id, enc, ciphertext) VALUES ($1, $2, $3, $4)',
            [fileIdValue, envelope.recipientId, envelope.enc, envelope.ciphertext],
          );
      });
      response.status(204).end();
    },
  );

  router.put(
    '/rooms/:roomId/files/:fileId/chunks/:index',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const fileIdValue = roomId.parse(request.params.fileId);
      const index = z.coerce
        .number()
        .int()
        .min(0)
        .max(MAX_CHUNKS - 1)
        .parse(request.params.index);
      const ciphertext = request.body as Buffer;
      requireCondition(
        Buffer.isBuffer(ciphertext) &&
          ciphertext.length >= 16 &&
          ciphertext.length <= CHUNK_BYTES + 16,
        413,
        'INVALID_CHUNK',
        'Encrypted chunk size is invalid.',
      );
      const digest = fingerprint(ciphertext);
      const result = await database.transaction(async (transaction) => {
        const [room] = await transaction.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
          [roomIdValue],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireOwner(transaction, room, request.session!.id);
        const [file] = await transaction.query<{
          owner_id: string;
          status: string;
          chunk_count: number;
          encrypted_bytes: string;
          encrypted_descriptor: Buffer | null;
        }>(
          'SELECT owner_id, status, chunk_count, encrypted_bytes::text AS encrypted_bytes, encrypted_descriptor FROM room_files WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [fileIdValue, roomIdValue],
        );
        requireCondition(
          file && file.owner_id === request.session!.id,
          404,
          'FILE_NOT_FOUND',
          'File not found.',
        );
        requireCondition(
          file.status === 'uploading',
          409,
          'UPLOAD_COMPLETE',
          'This upload has already completed.',
        );
        requireCondition(
          file.encrypted_descriptor,
          409,
          'METADATA_REQUIRED',
          'Set encrypted file metadata before uploading chunks.',
        );
        const [existing] = await transaction.query<{ sha256: string }>(
          'SELECT sha256 FROM room_file_chunks WHERE file_id = $1 AND chunk_index = $2',
          [fileIdValue, index],
        );
        if (existing) {
          requireCondition(
            existing.sha256 === digest,
            409,
            'CHUNK_CONFLICT',
            'A retry must send the original encrypted bytes.',
          );
          return 'retry';
        }
        const [existingCount] = await transaction.query<{ count: number }>(
          'SELECT count(*)::int AS count FROM room_file_chunks WHERE file_id = $1',
          [fileIdValue],
        );
        requireCondition(
          index <= existingCount.count,
          409,
          'CHUNK_ORDER',
          'Upload chunks must be sent in order.',
        );
        requireCondition(
          Number(file.encrypted_bytes) + ciphertext.length <=
            MAX_FILE_BYTES + MAX_CHUNKS * 16,
          413,
          'FILE_LIMIT',
          'The file exceeds the 250 MiB encrypted upload limit.',
        );
        const [usage] = await transaction.query<{ total: string }>(
          'SELECT COALESCE(SUM(encrypted_bytes), 0)::text AS total FROM room_files WHERE room_id = $1',
          [roomIdValue],
        );
        requireCondition(
          Number(usage.total) + ciphertext.length <= MAX_ROOM_BYTES,
          413,
          'ROOM_QUOTA',
          'The room has reached its encrypted storage limit.',
        );
        await transaction.query(
          'INSERT INTO room_file_chunks (file_id, chunk_index, ciphertext, sha256) VALUES ($1, $2, $3, $4)',
          [fileIdValue, index, ciphertext, digest],
        );
        await transaction.query(
          'UPDATE room_files SET chunk_count = chunk_count + 1, encrypted_bytes = encrypted_bytes + $2 WHERE id = $1',
          [fileIdValue, ciphertext.length],
        );
        return 'stored';
      });
      response
        .status(result === 'retry' ? 200 : 201)
        .set('X-Ciphertext-SHA256', digest)
        .json({ index, sha256: digest, status: result });
    },
  );

  router.post(
    '/rooms/:roomId/files/:fileId/complete',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const fileIdValue = roomId.parse(request.params.fileId);
      const { chunkCount, manifestSha256 } = z
        .object({
          chunkCount: z.number().int().min(1).max(MAX_CHUNKS),
          manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
        })
        .strict()
        .parse(request.body);
      const receipt = await database.transaction(async (transaction) => {
        const [room] = await transaction.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
          [roomIdValue],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireOwner(transaction, room, request.session!.id);
        const [file] = await transaction.query<{
          owner_id: string;
          status: string;
          chunk_count: number;
          encrypted_bytes: string;
          receipt: unknown;
          encrypted_descriptor: Buffer | null;
          manifest_sha256: string | null;
        }>(
          'SELECT owner_id, status, chunk_count, encrypted_bytes::text AS encrypted_bytes, receipt, encrypted_descriptor, manifest_sha256 FROM room_files WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [fileIdValue, roomIdValue],
        );
        requireCondition(
          file && file.owner_id === request.session!.id,
          404,
          'FILE_NOT_FOUND',
          'File not found.',
        );
        if (file.status === 'complete') {
          requireCondition(
            file.chunk_count === chunkCount &&
              file.manifest_sha256 === manifestSha256,
            409,
            'COMPLETION_CONFLICT',
            'The completion retry does not match the accepted upload.',
          );
          return file.receipt;
        }
        requireCondition(
          file.encrypted_descriptor,
          409,
          'METADATA_REQUIRED',
          'Encrypted metadata is missing.',
        );
        requireCondition(
          file.chunk_count === chunkCount,
          409,
          'CHUNKS_MISSING',
          'Upload is incomplete. Retry missing chunks before completing.',
        );
        const manifestHash = createHash('sha256').update(
          file.encrypted_descriptor,
        );
        for (let index = 0; index < chunkCount; index += 1) {
          const [chunk] = await transaction.query<{
            ciphertext: Buffer;
            sha256: string;
          }>(
            'SELECT ciphertext, sha256 FROM room_file_chunks WHERE file_id = $1 AND chunk_index = $2',
            [fileIdValue, index],
          );
          requireCondition(
            chunk && fingerprint(chunk.ciphertext) === chunk.sha256,
            409,
            'CHUNKS_INVALID',
            'Upload chunks are incomplete or corrupted.',
          );
          manifestHash.update(Buffer.from(chunk.sha256, 'hex'));
        }
        const [stillActive] = await transaction.query<{ active: boolean }>(
          "SELECT status = 'open' AND expires_at > clock_timestamp() AS active FROM rooms WHERE id = $1",
          [roomIdValue],
        );
        requireCondition(
          stillActive?.active,
          410,
          'ROOM_CLOSED',
          'This room is no longer exchanging files.',
        );
        const manifest = manifestHash.digest('hex');
        requireCondition(
          manifest === manifestSha256,
          422,
          'MANIFEST_MISMATCH',
          'The encrypted upload manifest does not match stored chunks.',
        );
        const value = {
          id: fileIdValue,
          manifestSha256: manifest,
          acceptedAt: new Date().toISOString(),
          encryptedBytes: Number(file.encrypted_bytes),
        };
        await transaction.query(
          "UPDATE room_files SET status = 'complete', manifest_sha256 = $2, receipt = $3, completed_at = clock_timestamp() WHERE id = $1",
          [fileIdValue, manifest, JSON.stringify(value)],
        );
        await recordActivity(transaction, roomIdValue, 'file_published');
        return value;
      });
      response.json({ receipt });
    },
  );

  router.delete(
    '/rooms/:roomId/files/:fileId',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const fileIdValue = roomId.parse(request.params.fileId);
      await database.transaction(async (transaction) => {
        const [room] = await transaction.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
          [roomIdValue],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireOwner(transaction, room, request.session!.id);
        const [file] = await transaction.query<{
          owner_id: string;
          status: string;
        }>(
          'SELECT owner_id, status FROM room_files WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [fileIdValue, roomIdValue],
        );
        requireCondition(
          file &&
            file.owner_id === request.session!.id && (!request.query.incompleteOnly || file.status === 'uploading'),
          404,
          'FILE_NOT_FOUND',
          'Upload not found.',
        );
        await transaction.query('DELETE FROM room_files WHERE id = $1', [fileIdValue]);
        if (file.status === 'complete') await recordActivity(transaction, roomIdValue, 'file_deleted');
      });
      response.status(204).end();
    },
  );

  router.get('/rooms/:roomId/files', async (request, response) => {
    const id = roomId.parse(request.params.roomId);
    const room = await roomPolicy(database, id);
    const role = await requireVisible(database, room, request.session!.id);
    const beforeValue = z
      .string()
      .base64url()
      .max(200)
      .optional()
      .parse(request.query.before);
    let before: { createdAt: string; id: string } | null = null;
    if (beforeValue) {
      try {
        before = z
          .object({ createdAt: z.iso.datetime(), id: roomId })
          .strict()
          .parse(
            JSON.parse(Buffer.from(beforeValue, 'base64url').toString('utf8')),
          );
      } catch {
        requireCondition(
          false,
          422,
          'INVALID_CURSOR',
          'File page cursor is invalid.',
        );
      }
    }
    const rows = await database.query<{
      id: string;
      owner_id: string;
      encrypted_descriptor: Buffer;
      envelope_enc: Buffer;
      envelope_ciphertext: Buffer;
      chunk_count: number;
      encrypted_bytes: string;
      manifest_sha256: string;
      receipt: unknown;
      created_at: Date;
      created_at_cursor: string;
      envelope_kind: 'room' | 'personal';
      room_shared: boolean;
    }>(
      `SELECT f.id, f.owner_id, f.encrypted_descriptor,
        COALESCE(CASE WHEN $5::boolean THEN shared.enc END, e.enc) AS envelope_enc,
        COALESCE(CASE WHEN $5::boolean THEN shared.ciphertext END, e.ciphertext) AS envelope_ciphertext,
        CASE WHEN $5::boolean AND shared.file_id IS NOT NULL THEN 'room' ELSE 'personal' END AS envelope_kind,
        shared.file_id IS NOT NULL AS room_shared,
        f.chunk_count, f.encrypted_bytes::text AS encrypted_bytes, f.manifest_sha256, f.receipt, f.created_at,
        to_char(f.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor
       FROM room_files f LEFT JOIN room_file_envelopes e ON e.file_id = f.id AND e.recipient_id = $2
       LEFT JOIN room_file_shared_envelopes shared ON shared.file_id = f.id
       WHERE (e.recipient_id IS NOT NULL OR ($5::boolean AND shared.file_id IS NOT NULL)) AND f.room_id = $1 AND f.status = 'complete'
         AND ($3::timestamptz IS NULL OR (f.created_at, f.id) < ($3::timestamptz, $4::uuid))
       ORDER BY f.created_at DESC, f.id DESC LIMIT 51`,
      [
        id,
        request.session!.id,
        before?.createdAt ?? null,
        before?.id ?? null,
        role === 'recipient',
      ],
    );
    const pageRows = rows.slice(0, 50);
    const last = pageRows.at(-1);
    const nextCursor =
      rows.length > 50 && last
        ? Buffer.from(
            JSON.stringify({ createdAt: last.created_at_cursor, id: last.id }),
          ).toString('base64url')
        : null;
    response.json({
      files: pageRows.map((row) => ({
        id: row.id,
        descriptor: Buffer.from(row.encrypted_descriptor).toString('base64'),
        envelope: {
          enc: Buffer.from(row.envelope_enc).toString('base64'),
          ciphertext: Buffer.from(row.envelope_ciphertext).toString('base64'),
        },
        envelopeKind: row.envelope_kind,
        roomShared: row.room_shared,
        chunkCount: row.chunk_count,
        encryptedBytes: Number(row.encrypted_bytes),
        manifestSha256: row.manifest_sha256,
        receipt: row.receipt,
        createdAt: row.created_at.toISOString(),
      })),
      nextCursor,
    });
  });

  router.get(
    '/rooms/:roomId/files/:fileId/chunks/:index',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const fileIdValue = roomId.parse(request.params.fileId);
      const index = z.coerce
        .number()
        .int()
        .min(0)
        .max(MAX_CHUNKS - 1)
        .parse(request.params.index);
      const room = await roomPolicy(database, roomIdValue);
      const role = await requireVisible(database, room, request.session!.id);
      const [file] = await database.query<{
        owner_id: string;
        chunk_count: number;
      }>(
        "SELECT owner_id, chunk_count FROM room_files WHERE id = $1 AND room_id = $2 AND status = 'complete'",
        [fileIdValue, roomIdValue],
      );
      if (file && role === 'recipient') {
        const [envelope] = await database.query<{ recipient_id: string }>(
          `SELECT recipient_id FROM room_file_envelopes WHERE file_id = $1 AND recipient_id = $2
           UNION ALL SELECT $2::uuid AS recipient_id FROM room_file_shared_envelopes WHERE file_id = $1 LIMIT 1`,
          [fileIdValue, request.session!.id],
        );
        requireCondition(
          envelope,
          404,
          'FILE_NOT_FOUND',
          'File not found.',
        );
      } else
        requireCondition(
          file && file.owner_id === request.session!.id,
          404,
          'FILE_NOT_FOUND',
          'File not found.',
        );
      requireCondition(
        index < file!.chunk_count,
        404,
        'CHUNK_NOT_FOUND',
        'Chunk not found.',
      );
      const [chunk] = await database.query<{
        ciphertext: Buffer;
        sha256: string;
      }>(
        'SELECT ciphertext, sha256 FROM room_file_chunks WHERE file_id = $1 AND chunk_index = $2',
        [fileIdValue, index],
      );
      requireCondition(
        chunk && fingerprint(chunk.ciphertext) === chunk.sha256,
        500,
        'CHUNK_CORRUPT',
        'Stored encrypted data failed integrity verification.',
      );
      response.setHeader('Content-Type', 'application/octet-stream');
      response.setHeader('Content-Length', chunk.ciphertext.length);
      response.setHeader('X-Ciphertext-SHA256', chunk.sha256);
      response.send(Buffer.from(chunk.ciphertext));
    },
  );

  router.put('/rooms/:roomId/files/:fileId/recipients/:recipientId', async (request, response) => {
    const id = roomId.parse(request.params.roomId), fileId = roomId.parse(request.params.fileId), recipientId = roomId.parse(request.params.recipientId);
    const input = z.object({ fingerprint: z.string().regex(/^[a-f0-9]{64}$/), enc: b64, ciphertext: b64 }).strict().parse(request.body);
    const enc = Buffer.from(input.enc, 'base64'), ciphertext = Buffer.from(input.ciphertext, 'base64');
    requireCondition(enc.length === 65 && ciphertext.length === 48, 422, 'INVALID_ENCRYPTION', 'Recipient envelope is invalid.');
    await database.transaction(async tx => {
      const [room] = await tx.query<RoomPolicy>('SELECT id, owner_id, status, expires_at FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      await requireOwner(tx, room, request.session!.id);
      const [recipient] = await tx.query<{ fingerprint: string }>(`SELECT k.fingerprint FROM session_recipient_keys k JOIN memberships m
        ON m.room_id = k.room_id AND m.session_id = k.session_id JOIN sessions s ON s.id = m.session_id
        WHERE k.room_id = $1 AND k.session_id = $2 AND m.status = 'approved' AND s.expires_at > clock_timestamp()
        AND (m.credential_expires_at IS NULL OR m.credential_expires_at > clock_timestamp())`, [id, recipientId]);
      requireCondition(recipient?.fingerprint === input.fingerprint, 409, 'RECIPIENT_CHANGED', 'The approved recipient key changed. Refresh before granting access.');
      const [file] = await tx.query("SELECT id FROM room_files WHERE id = $1 AND room_id = $2 AND status = 'complete'", [fileId, id]);
      requireCondition(file, 404, 'FILE_NOT_FOUND', 'Published file not found.');
      await tx.query(`INSERT INTO room_file_envelopes(file_id, recipient_id, enc, ciphertext) VALUES ($1, $2, $3, $4)
        ON CONFLICT(file_id, recipient_id) DO UPDATE SET enc = EXCLUDED.enc, ciphertext = EXCLUDED.ciphertext`, [fileId, recipientId, enc, ciphertext]);
      await recordActivity(tx, id, 'file_access_granted');
    });
    response.status(204).end();
  });

  // Upgrade old publications once in the organizer browser. Only envelopes
  // change; ciphertext, filenames and file secrets never reach the API.
  router.post('/rooms/:id/files/room-access', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ fingerprint: z.string().regex(/^[a-f0-9]{64}$/), envelopes: z.array(z.object({ fileId: roomId, enc: b64, ciphertext: b64 }).strict()).max(1000) }).strict().parse(request.body);
    await database.transaction(async tx => {
      const [room] = await tx.query<RoomPolicy>('SELECT id, owner_id, status, expires_at FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      await requireOwner(tx, room, request.session!.id);
      const [key] = await tx.query<{ fingerprint: string }>('SELECT fingerprint FROM room_access_keys WHERE room_id = $1', [id]);
      requireCondition(key?.fingerprint === input.fingerprint, 409, 'KEY_CHANGED', 'Reload room access before continuing.');
      for (const envelope of input.envelopes) {
        requireCondition(Buffer.from(envelope.enc, 'base64').length === 65 && Buffer.from(envelope.ciphertext, 'base64').length === 48, 422, 'INVALID_ENCRYPTION', 'Room envelope is invalid.');
        const [file] = await tx.query("SELECT id FROM room_files WHERE id = $1 AND room_id = $2 AND status = 'complete'", [envelope.fileId, id]);
        requireCondition(file, 404, 'FILE_NOT_FOUND', 'Published file not found.');
        const inserted = await tx.query('INSERT INTO room_file_shared_envelopes(file_id, fingerprint, enc, ciphertext) VALUES ($1, $2, $3, $4) ON CONFLICT(file_id) DO NOTHING RETURNING file_id', [envelope.fileId, input.fingerprint, Buffer.from(envelope.enc, 'base64'), Buffer.from(envelope.ciphertext, 'base64')]);
        if (inserted.length) await recordActivity(tx, id, 'file_access_granted');
      }
    });
    response.status(204).end();
  });

  router.post('/rooms/:id/files/grants', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ recipientId: roomId, fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
      envelopes: z.array(z.object({ fileId: roomId, enc: b64, ciphertext: b64 }).strict()).max(1000),
    }).strict().parse(request.body);
    await database.transaction(async tx => {
      const [room] = await tx.query<RoomPolicy>('SELECT id, owner_id, status, expires_at FROM rooms WHERE id = $1 FOR UPDATE', [id]);
      requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      await requireOwner(tx, room, request.session!.id);
      const [recipient] = await tx.query<{ fingerprint: string }>(`SELECT k.fingerprint FROM session_recipient_keys k JOIN memberships m
        ON m.room_id = k.room_id AND m.session_id = k.session_id JOIN sessions s ON s.id = m.session_id
        WHERE k.room_id = $1 AND k.session_id = $2 AND m.status = 'approved' AND s.expires_at > clock_timestamp()
        AND (m.credential_expires_at IS NULL OR m.credential_expires_at > clock_timestamp())
        AND NOT EXISTS (SELECT 1 FROM credential_revocations v WHERE v.room_id = m.room_id AND v.nullifier = m.credential_nullifier)`, [id, input.recipientId]);
      requireCondition(recipient?.fingerprint === input.fingerprint, 409, 'RECIPIENT_CHANGED', 'Refresh the approved recipient key.');
      requireCondition(new Set(input.envelopes.map(e => e.fileId)).size === input.envelopes.length, 422, 'INVALID_INPUT', 'Duplicate file grants are not allowed.');
      for (const envelope of input.envelopes) {
        const enc = Buffer.from(envelope.enc, 'base64'), ciphertext = Buffer.from(envelope.ciphertext, 'base64');
        requireCondition(enc.length === 65 && ciphertext.length === 48, 422, 'INVALID_ENCRYPTION', 'Recipient envelope is invalid.');
        const [file] = await tx.query("SELECT id FROM room_files WHERE id = $1 AND room_id = $2 AND status = 'complete'", [envelope.fileId, id]);
        requireCondition(file, 404, 'FILE_NOT_FOUND', 'Published file not found.');
        await tx.query(`INSERT INTO room_file_envelopes(file_id, recipient_id, enc, ciphertext) VALUES ($1, $2, $3, $4)
          ON CONFLICT(file_id, recipient_id) DO UPDATE SET enc = EXCLUDED.enc, ciphertext = EXCLUDED.ciphertext`, [envelope.fileId, input.recipientId, enc, ciphertext]);
      }
      if (input.envelopes.length) await recordActivity(tx, id, 'file_access_granted');
    });
    response.status(204).end();
  });

  router.get('/rooms/:roomId/files/:fileId/upload', async (request, response) => {
    const id = roomId.parse(request.params.roomId), fileId = roomId.parse(request.params.fileId);
    const room = await roomPolicy(database, id);
    await requireOwner(database, room, request.session!.id);
    const [file] = await database.query<{ status: string; encrypted_descriptor: Buffer | null; receipt: unknown }>('SELECT status, encrypted_descriptor, receipt FROM room_files WHERE id = $1 AND room_id = $2', [fileId, id]);
    requireCondition(file, 404, 'FILE_NOT_FOUND', 'Upload not found.');
    const chunks = await database.query<{ index: number; sha256: string }>('SELECT chunk_index AS index, sha256 FROM room_file_chunks WHERE file_id = $1 ORDER BY chunk_index', [fileId]);
    response.json({ status: file.status, descriptor: file.encrypted_descriptor ? Buffer.from(file.encrypted_descriptor).toString('base64') : null, receipt: file.receipt, chunks });
  });

  return router;
}
