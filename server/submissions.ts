import { createHash, createPublicKey } from 'node:crypto';
import express from 'express';
import { Router } from 'express';
import { z } from 'zod';
import type { Database, Queries } from './database.js';
import { requireCondition } from './errors.js';
import { roomId } from '../shared/rooms.js';

const MAX_ROOM_BYTES = 5 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES = 250 * 1024 * 1024;
const MAX_CHUNKS = 250;
const CHUNK_BYTES = 1024 * 1024;
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
    'This room is no longer accepting submissions.',
  );
  return room;
}

async function requireSubmitter(
  queries: Queries,
  room: RoomPolicy,
  sessionId: string,
) {
  requireCondition(
    room.status === 'open' && !room.is_expired,
    410,
    'ROOM_CLOSED',
    'This room is no longer accepting submissions.',
  );
  requireCondition(
    room.owner_id !== sessionId,
    403,
    'SUBMITTER_REQUIRED',
    'Organizers cannot submit to their own inbox.',
  );
  const [membership] = await queries.query<{ status: string }>(
    `SELECT m.status FROM memberships m JOIN sessions s ON s.id = m.session_id
     WHERE m.room_id = $1 AND m.session_id = $2 AND s.expires_at > clock_timestamp()`,
    [room.id, sessionId],
  );
  requireCondition(
    membership?.status === 'approved',
    403,
    'ADMISSION_REQUIRED',
    'Organizer approval is required.',
  );
}

async function requireVisible(
  queries: Queries,
  room: RoomPolicy,
  sessionId: string,
) {
  if (room.owner_id === sessionId) return 'owner';
  const [membership] = await queries.query<{ status: string }>(
    `SELECT m.status FROM memberships m JOIN sessions s ON s.id = m.session_id
     WHERE m.room_id = $1 AND m.session_id = $2 AND s.expires_at > clock_timestamp()`,
    [room.id, sessionId],
  );
  requireCondition(
    membership?.status === 'approved',
    403,
    'ADMISSION_REQUIRED',
    'Organizer approval is required.',
  );
  return 'submitter';
}

export function submissionRoutes(database: Database) {
  const router = Router();
  router.use(
    '/rooms/:roomId/submissions/:submissionId/chunks/:index',
    (request, response, next) => {
      if (request.method !== 'PUT') return next();
      void (async () => {
        const pathRoom = roomId.parse(request.params.roomId);
        const submissionId = roomId.parse(request.params.submissionId);
        const [room] = await database.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1',
          [pathRoom],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireSubmitter(database, room, request.session!.id);
        const [submission] = await database.query<{
          submitter_id: string;
          status: string;
          encrypted_descriptor: Buffer | null;
        }>(
          'SELECT submitter_id, status, encrypted_descriptor FROM private_submissions WHERE id = $1 AND room_id = $2',
          [submissionId, pathRoom],
        );
        requireCondition(
          submission && submission.submitter_id === request.session!.id,
          404,
          'SUBMISSION_NOT_FOUND',
          'Submission not found.',
        );
        requireCondition(
          submission.status === 'uploading' && submission.encrypted_descriptor,
          409,
          'UPLOAD_UNAVAILABLE',
          'This upload is no longer accepting chunks.',
        );
        express.raw({
          type: 'application/octet-stream',
          limit: CHUNK_BYTES + 16,
        })(request, response, next);
      })().catch(next);
    },
  );

  router.get('/rooms/:id/submissions/keys', async (request, response) => {
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
        'This room is no longer accepting submissions.',
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
      'INBOX_NOT_ENABLED',
      'The organizer has not enabled the encrypted inbox.',
    );
    if (room.owner_id === request.session!.id) {
      response.json({
        ownerPublicKey: Buffer.from(ownerKey.publicKey).toString('base64'),
        ownerFingerprint: ownerKey.fingerprint,
      });
      return;
    }
    const [submitterKey] = await database.query<{ fingerprint: string }>(
      'SELECT fingerprint FROM session_recipient_keys WHERE room_id = $1 AND session_id = $2',
      [id, request.session!.id],
    );
    response.json({
      ownerPublicKey: Buffer.from(ownerKey.publicKey).toString('base64'),
      ownerFingerprint: ownerKey.fingerprint,
      submitterFingerprint: submitterKey?.fingerprint ?? null,
    });
  });

  router.post('/rooms/:id/submissions/owner-key', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = z.object({ publicKey: b64 }).strict().parse(request.body);
    const publicKey = Buffer.from(input.publicKey, 'base64');
    requireCondition(
      validP256(publicKey),
      422,
      'INVALID_KEY',
      'Organizer key is invalid.',
    );
    const room = await database.transaction(async (transaction) => {
      const [value] = await transaction.query<RoomPolicy>(
        'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
        [id],
      );
      requireCondition(value, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      requireCondition(
        value.owner_id === request.session!.id,
        403,
        'OWNER_REQUIRED',
        'Only the organizer can enable the inbox.',
      );
      requireCondition(
        value.status !== 'closed' && !value.is_expired,
        410,
        'ROOM_CLOSED',
        'This room has closed.',
      );
      const digest = fingerprint(publicKey);
      const existing = await transaction.query<{ fingerprint: string }>(
        'SELECT fingerprint FROM room_recipient_keys WHERE room_id = $1',
        [id],
      );
      requireCondition(
        !existing.length || existing[0].fingerprint === digest,
        409,
        'KEY_IMMUTABLE',
        'The organizer key is already registered and cannot be replaced.',
      );
      if (!existing.length)
        await transaction.query(
          'INSERT INTO room_recipient_keys (room_id, public_key, fingerprint) VALUES ($1, $2, $3)',
          [id, publicKey, digest],
        );
      return digest;
    });
    response.status(201).json({ fingerprint: room });
  });

  router.post(
    '/rooms/:id/submissions/submitter-key',
    async (request, response) => {
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
        await requireSubmitter(transaction, room, request.session!.id);
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
        if (!existing.length)
          await transaction.query(
            'INSERT INTO session_recipient_keys (room_id, session_id, public_key, fingerprint) VALUES ($1, $2, $3, $4)',
            [id, request.session!.id, publicKey, value],
          );
        return value;
      });
      response.status(201).json({ fingerprint: digest });
    },
  );

  router.post('/rooms/:id/submissions', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { uploadId: idValue } = z
      .object({ uploadId: roomId })
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
      await requireSubmitter(transaction, room, request.session!.id);
      const [ownerKey] = await transaction.query<{ public_key: Buffer }>(
        'SELECT public_key FROM room_recipient_keys WHERE room_id = $1',
        [id],
      );
      const [submitterKey] = await transaction.query<{ public_key: Buffer }>(
        'SELECT public_key FROM session_recipient_keys WHERE room_id = $1 AND session_id = $2',
        [id, request.session!.id],
      );
      requireCondition(
        ownerKey && submitterKey,
        409,
        'KEYS_REQUIRED',
        'Set up the organizer and browser keys before uploading.',
      );
      const [existing] = await transaction.query<{
        submitter_id: string;
        status: string;
        room_id: string;
        receipt: unknown;
      }>(
        'SELECT submitter_id, status, room_id, receipt FROM private_submissions WHERE id = $1 FOR UPDATE',
        [idValue],
      );
      if (existing) {
        requireCondition(
          existing.room_id === id &&
            existing.submitter_id === request.session!.id,
          409,
          'UPLOAD_ID_CONFLICT',
          'This upload reference is already in use.',
        );
        completed = existing.status === 'complete';
        if (completed) completionReceipt = existing.receipt;
        return;
      }
      await transaction.query(
        "DELETE FROM private_submissions WHERE room_id = $1 AND status = 'uploading' AND created_at < clock_timestamp() - interval '24 hours'",
        [id],
      );
      const [usage] = await transaction.query<{ total: string }>(
        `SELECT COALESCE(SUM(encrypted_bytes), 0)::text AS total FROM private_submissions WHERE room_id = $1`,
        [id],
      );
      requireCondition(
        Number(usage.total) < MAX_ROOM_BYTES,
        413,
        'ROOM_QUOTA',
        'The room has reached its encrypted storage limit.',
      );
      const [objectCount] = await transaction.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM private_submissions WHERE room_id = $1',
        [id],
      );
      requireCondition(
        objectCount.count < 1000,
        413,
        'OBJECT_LIMIT',
        'The room has reached its 1,000-submission limit.',
      );
      const [pending] = await transaction.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM private_submissions WHERE room_id = $1 AND status = 'uploading'",
        [id],
      );
      requireCondition(
        pending.count < 100,
        429,
        'UPLOADS_PENDING',
        'Too many uploads are already in progress for this room.',
      );
      const [mine] = await transaction.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM private_submissions WHERE room_id = $1 AND submitter_id = $2 AND status = 'uploading'",
        [id, request.session!.id],
      );
      requireCondition(
        mine.count < 10,
        429,
        'UPLOADS_PENDING',
        'Finish or retry your existing uploads before starting another.',
      );
      const inserted = await transaction.query(
        'INSERT INTO private_submissions (id, room_id, submitter_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING RETURNING id',
        [idValue, id, request.session!.id],
      );
      requireCondition(
        inserted.length,
        409,
        'UPLOAD_ID_CONFLICT',
        'This upload reference is already in use.',
      );
    });
    response
      .status(201)
      .json({
        id: idValue,
        complete: completed,
        ...(completed ? { receipt: completionReceipt } : {}),
        chunkBytes: CHUNK_BYTES,
        maxFileBytes: MAX_FILE_BYTES,
      });
  });

  router.put(
    '/rooms/:roomId/submissions/:submissionId/metadata',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const submissionId = roomId.parse(request.params.submissionId);
      const input = z
        .object({
          descriptor: b64,
          ownerEnvelope: z.object({ enc: b64, ciphertext: b64 }).strict(),
          submitterEnvelope: z.object({ enc: b64, ciphertext: b64 }).strict(),
        })
        .strict()
        .parse(request.body);
      const descriptor = Buffer.from(input.descriptor, 'base64');
      const envelopes = [input.ownerEnvelope, input.submitterEnvelope].map(
        (envelope) => ({
          enc: Buffer.from(envelope.enc, 'base64'),
          ciphertext: Buffer.from(envelope.ciphertext, 'base64'),
        }),
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
        'Encrypted submission metadata is invalid.',
      );
      await database.transaction(async (transaction) => {
        const [room] = await transaction.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
          [roomIdValue],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        await requireSubmitter(transaction, room, request.session!.id);
        const [submission] = await transaction.query<{
          submitter_id: string;
          status: string;
          encrypted_descriptor: Buffer | null;
        }>(
          'SELECT submitter_id, status, encrypted_descriptor FROM private_submissions WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [submissionId, roomIdValue],
        );
        requireCondition(
          submission && submission.submitter_id === request.session!.id,
          404,
          'SUBMISSION_NOT_FOUND',
          'Submission not found.',
        );
        requireCondition(
          submission.status === 'uploading',
          409,
          'UPLOAD_COMPLETE',
          'This upload has already completed.',
        );
        if (submission.encrypted_descriptor) {
          const stored = await transaction.query<{
            recipient_id: string;
            enc: Buffer;
            ciphertext: Buffer;
          }>(
            'SELECT recipient_id, enc, ciphertext FROM submission_envelopes WHERE submission_id = $1',
            [submissionId],
          );
          const owner = stored.find(
            (row) => row.recipient_id === room.owner_id,
          );
          const submitter = stored.find(
            (row) => row.recipient_id === request.session!.id,
          );
          const identical =
            Buffer.from(submission.encrypted_descriptor).equals(descriptor) &&
            owner &&
            submitter &&
            Buffer.from(owner.enc).equals(envelopes[0].enc) &&
            Buffer.from(owner.ciphertext).equals(envelopes[0].ciphertext) &&
            Buffer.from(submitter.enc).equals(envelopes[1].enc) &&
            Buffer.from(submitter.ciphertext).equals(envelopes[1].ciphertext);
          requireCondition(
            identical,
            409,
            'METADATA_CONFLICT',
            'A retry must send the original encrypted metadata and envelopes.',
          );
          return;
        }
        await transaction.query(
          'UPDATE private_submissions SET encrypted_descriptor = $2 WHERE id = $1',
          [submissionId, descriptor],
        );
        await transaction.query(
          'INSERT INTO submission_envelopes (submission_id, recipient_id, enc, ciphertext) VALUES ($1, $2, $3, $4), ($1, $5, $6, $7)',
          [
            submissionId,
            room.owner_id,
            envelopes[0].enc,
            envelopes[0].ciphertext,
            request.session!.id,
            envelopes[1].enc,
            envelopes[1].ciphertext,
          ],
        );
      });
      response.status(204).end();
    },
  );

  router.put(
    '/rooms/:roomId/submissions/:submissionId/chunks/:index',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const submissionId = roomId.parse(request.params.submissionId);
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
        await requireSubmitter(transaction, room, request.session!.id);
        const [submission] = await transaction.query<{
          submitter_id: string;
          status: string;
          chunk_count: number;
          encrypted_bytes: string;
          encrypted_descriptor: Buffer | null;
        }>(
          'SELECT submitter_id, status, chunk_count, encrypted_bytes::text AS encrypted_bytes, encrypted_descriptor FROM private_submissions WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [submissionId, roomIdValue],
        );
        requireCondition(
          submission && submission.submitter_id === request.session!.id,
          404,
          'SUBMISSION_NOT_FOUND',
          'Submission not found.',
        );
        requireCondition(
          submission.status === 'uploading',
          409,
          'UPLOAD_COMPLETE',
          'This upload has already completed.',
        );
        requireCondition(
          submission.encrypted_descriptor,
          409,
          'METADATA_REQUIRED',
          'Set encrypted file metadata before uploading chunks.',
        );
        requireCondition(
          index < MAX_CHUNKS,
          413,
          'CHUNK_LIMIT',
          'The upload exceeds the chunk limit.',
        );
        const [existing] = await transaction.query<{ sha256: string }>(
          'SELECT sha256 FROM submission_chunks WHERE submission_id = $1 AND chunk_index = $2',
          [submissionId, index],
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
          'SELECT count(*)::int AS count FROM submission_chunks WHERE submission_id = $1',
          [submissionId],
        );
        requireCondition(
          index <= existingCount.count,
          409,
          'CHUNK_ORDER',
          'Upload chunks must be sent in order.',
        );
        requireCondition(
          Number(submission.encrypted_bytes) + ciphertext.length <=
            MAX_FILE_BYTES + MAX_CHUNKS * 16,
          413,
          'FILE_LIMIT',
          'The file exceeds the 250 MiB encrypted upload limit.',
        );
        const [usage] = await transaction.query<{ total: string }>(
          'SELECT COALESCE(SUM(encrypted_bytes), 0)::text AS total FROM private_submissions WHERE room_id = $1',
          [roomIdValue],
        );
        requireCondition(
          Number(usage.total) + ciphertext.length <= MAX_ROOM_BYTES,
          413,
          'ROOM_QUOTA',
          'The room has reached its encrypted storage limit.',
        );
        await transaction.query(
          'INSERT INTO submission_chunks (submission_id, chunk_index, ciphertext, sha256) VALUES ($1, $2, $3, $4)',
          [submissionId, index, ciphertext, digest],
        );
        await transaction.query(
          'UPDATE private_submissions SET chunk_count = chunk_count + 1, encrypted_bytes = encrypted_bytes + $2 WHERE id = $1',
          [submissionId, ciphertext.length],
        );
        return 'stored';
      });
      response
        .status(result === 'retry' ? 200 : 201)
        .json({ index, sha256: digest, status: result });
    },
  );

  router.post(
    '/rooms/:roomId/submissions/:submissionId/complete',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const submissionId = roomId.parse(request.params.submissionId);
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
        await requireSubmitter(transaction, room, request.session!.id);
        const [submission] = await transaction.query<{
          submitter_id: string;
          status: string;
          chunk_count: number;
          encrypted_bytes: string;
          receipt: unknown;
          encrypted_descriptor: Buffer | null;
          manifest_sha256: string | null;
        }>(
          'SELECT submitter_id, status, chunk_count, encrypted_bytes::text AS encrypted_bytes, receipt, encrypted_descriptor, manifest_sha256 FROM private_submissions WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [submissionId, roomIdValue],
        );
        requireCondition(
          submission && submission.submitter_id === request.session!.id,
          404,
          'SUBMISSION_NOT_FOUND',
          'Submission not found.',
        );
        if (submission.status === 'complete') {
          requireCondition(
            submission.chunk_count === chunkCount &&
              submission.manifest_sha256 === manifestSha256,
            409,
            'COMPLETION_CONFLICT',
            'The completion retry does not match the accepted upload.',
          );
          return submission.receipt;
        }
        requireCondition(
          submission.encrypted_descriptor,
          409,
          'METADATA_REQUIRED',
          'Encrypted metadata is missing.',
        );
        requireCondition(
          submission.chunk_count === chunkCount,
          409,
          'CHUNKS_MISSING',
          'Upload is incomplete. Retry missing chunks before completing.',
        );
        const manifestHash = createHash('sha256').update(
          submission.encrypted_descriptor,
        );
        for (let index = 0; index < chunkCount; index += 1) {
          const [chunk] = await transaction.query<{
            ciphertext: Buffer;
            sha256: string;
          }>(
            'SELECT ciphertext, sha256 FROM submission_chunks WHERE submission_id = $1 AND chunk_index = $2',
            [submissionId, index],
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
          'This room is no longer accepting submissions.',
        );
        const manifest = manifestHash.digest('hex');
        requireCondition(
          manifest === manifestSha256,
          422,
          'MANIFEST_MISMATCH',
          'The encrypted upload manifest does not match stored chunks.',
        );
        const value = {
          id: submissionId,
          manifestSha256: manifest,
          acceptedAt: new Date().toISOString(),
          encryptedBytes: Number(submission.encrypted_bytes),
        };
        await transaction.query(
          "UPDATE private_submissions SET status = 'complete', manifest_sha256 = $2, receipt = $3, completed_at = clock_timestamp() WHERE id = $1",
          [submissionId, manifest, JSON.stringify(value)],
        );
        return value;
      });
      response.json({ receipt });
    },
  );

  router.delete(
    '/rooms/:roomId/submissions/:submissionId',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const submissionId = roomId.parse(request.params.submissionId);
      await database.transaction(async (transaction) => {
        const [room] = await transaction.query<RoomPolicy>(
          'SELECT id, owner_id, status, expires_at, expires_at <= clock_timestamp() AS is_expired FROM rooms WHERE id = $1 FOR UPDATE',
          [roomIdValue],
        );
        requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
        requireCondition(
          room.status === 'open' && !room.is_expired,
          410,
          'ROOM_CLOSED',
          'This room no longer accepts upload changes.',
        );
        await requireSubmitter(transaction, room, request.session!.id);
        const [submission] = await transaction.query<{
          submitter_id: string;
          status: string;
        }>(
          'SELECT submitter_id, status FROM private_submissions WHERE id = $1 AND room_id = $2 FOR UPDATE',
          [submissionId, roomIdValue],
        );
        requireCondition(
          submission &&
            submission.submitter_id === request.session!.id &&
            submission.status === 'uploading',
          404,
          'SUBMISSION_NOT_FOUND',
          'Upload not found.',
        );
        await transaction.query(
          'DELETE FROM private_submissions WHERE id = $1',
          [submissionId],
        );
      });
      response.status(204).end();
    },
  );

  router.get('/rooms/:roomId/submissions', async (request, response) => {
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
          'Submission page cursor is invalid.',
        );
      }
    }
    const rows = await database.query<{
      id: string;
      submitter_id: string;
      encrypted_descriptor: Buffer;
      envelope_enc: Buffer;
      envelope_ciphertext: Buffer;
      chunk_count: number;
      encrypted_bytes: string;
      manifest_sha256: string;
      receipt: unknown;
      created_at: Date;
      created_at_cursor: string;
    }>(
      `SELECT s.id, s.submitter_id, s.encrypted_descriptor, e.enc AS envelope_enc, e.ciphertext AS envelope_ciphertext,
        s.chunk_count, s.encrypted_bytes::text AS encrypted_bytes, s.manifest_sha256, s.receipt, s.created_at,
        to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor
       FROM private_submissions s JOIN submission_envelopes e ON e.submission_id = s.id AND e.recipient_id = $2
       WHERE s.room_id = $1 AND s.status = 'complete' AND ($3 = 'owner' OR s.submitter_id = $2)
         AND ($4::timestamptz IS NULL OR (s.created_at, s.id) < ($4::timestamptz, $5::uuid))
       ORDER BY s.created_at DESC, s.id DESC LIMIT 51`,
      [
        id,
        request.session!.id,
        role,
        before?.createdAt ?? null,
        before?.id ?? null,
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
      submissions: pageRows.map((row) => ({
        id: row.id,
        descriptor: Buffer.from(row.encrypted_descriptor).toString('base64'),
        envelope: {
          enc: Buffer.from(row.envelope_enc).toString('base64'),
          ciphertext: Buffer.from(row.envelope_ciphertext).toString('base64'),
        },
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
    '/rooms/:roomId/submissions/:submissionId/chunks/:index',
    async (request, response) => {
      const roomIdValue = roomId.parse(request.params.roomId);
      const submissionId = roomId.parse(request.params.submissionId);
      const index = z.coerce
        .number()
        .int()
        .min(0)
        .max(MAX_CHUNKS - 1)
        .parse(request.params.index);
      const room = await roomPolicy(database, roomIdValue);
      const role = await requireVisible(database, room, request.session!.id);
      const [submission] = await database.query<{
        submitter_id: string;
        chunk_count: number;
      }>(
        "SELECT submitter_id, chunk_count FROM private_submissions WHERE id = $1 AND room_id = $2 AND status = 'complete'",
        [submissionId, roomIdValue],
      );
      requireCondition(
        submission &&
          (role === 'owner' || submission.submitter_id === request.session!.id),
        404,
        'SUBMISSION_NOT_FOUND',
        'Submission not found.',
      );
      requireCondition(
        index < submission.chunk_count,
        404,
        'CHUNK_NOT_FOUND',
        'Chunk not found.',
      );
      const [chunk] = await database.query<{
        ciphertext: Buffer;
        sha256: string;
      }>(
        'SELECT ciphertext, sha256 FROM submission_chunks WHERE submission_id = $1 AND chunk_index = $2',
        [submissionId, index],
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

  return router;
}
