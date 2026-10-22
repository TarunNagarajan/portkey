import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Router } from 'express';
import { Group } from '@semaphore-protocol/group';
import { verifyProof, type SemaphoreProof } from '@semaphore-protocol/proof';
import { z } from 'zod';
import { joinCode, roomId } from '../shared/rooms.js';
import {
  WORKSHOP_BASE_FIELD,
  WORKSHOP_PROOF_DEPTH,
  WORKSHOP_PROOF_VERSION,
  WORKSHOP_SCALAR_FIELD,
  workshopMessage,
  workshopScope,
} from '../shared/workshopProof.js';
import type { Database, Queries } from './database.js';
import { HttpError, requireCondition } from './errors.js';
import { recordActivity } from './activity.js';
import {
  admissionFix,
  clock,
  geoOf,
  lockRoom,
  requireActive,
  requireOpen,
  requireOwner,
} from './rooms.js';

const issueInput = z.object({ count: z.number().int().min(1).max(20) }).strict();
const revokeInput = z.object({ status: z.literal('revoked') }).strict();
const canonicalDecimalPattern = /^(0|[1-9][0-9]{0,76})$/;
const decimal = z.string().max(77).regex(canonicalDecimalPattern);
const fieldDecimal = decimal.refine((value) => canonicalDecimalPattern.test(value) && BigInt(value) < WORKSHOP_SCALAR_FIELD);
const commitmentDecimal = fieldDecimal.refine((value) => canonicalDecimalPattern.test(value) && BigInt(value) > 0n);
const pointDecimal = decimal.refine((value) => canonicalDecimalPattern.test(value) && BigInt(value) < WORKSHOP_BASE_FIELD);
const proofSchema = z.object({
  merkleTreeDepth: z.literal(WORKSHOP_PROOF_DEPTH),
  merkleTreeRoot: fieldDecimal,
  message: fieldDecimal,
  nullifier: fieldDecimal,
  scope: fieldDecimal,
  points: z.tuple([
    pointDecimal, pointDecimal, pointDecimal, pointDecimal,
    pointDecimal, pointDecimal, pointDecimal, pointDecimal,
  ]),
}).strict();
const enrollInput = z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{43}$/), commitment: commitmentDecimal }).strict();
const proveInput = z.object({
  challengeId: z.uuid(),
  proof: proofSchema,
  label: z.string().trim().min(1).max(50).optional(),
  lat: z.number().min(-90).max(90).optional(),
  lng: z.number().min(-180).max(180).optional(),
  accuracyM: z.number().min(0).max(1000).optional(),
  timestamp: z.iso.datetime({ offset: true }).optional(),
}).strict();

const digest = (token: string) => createHash('sha256').update(Buffer.from(token, 'base64url')).digest();
const inviteError = () => {
  throw new HttpError(403, 'ENROLLMENT_INVITE_INVALID', 'This enrollment link is invalid, unavailable, or already used. Ask the organizer for a new link.');
};
const proofError = () => {
  throw new HttpError(403, 'WORKSHOP_PROOF_INVALID', 'This membership proof is invalid or no longer available. Refresh and try again.');
};

interface InviteRow {
  id: string;
  invite_number: number;
  created_at: Date;
  revoked_at: Date | null;
  enrolled_commitment: string | null;
  token_digest?: Buffer;
}

function inviteView(row: InviteRow, terminal: boolean) {
  return {
    id: row.id,
    number: row.invite_number,
    createdAt: row.created_at.toISOString(),
    revokedAt: row.revoked_at?.toISOString() ?? null,
    status: row.revoked_at ? 'revoked' : row.enrolled_commitment ? 'enrolled' : terminal ? 'expired' : 'available',
  };
}

async function lockRoomByCode(queries: Queries, code: string) {
  const [found] = await queries.query<{ id: string }>('SELECT id FROM rooms WHERE join_code = $1', [code]);
  requireCondition(found, 404, 'ROOM_NOT_FOUND', 'Room not found.');
  return lockRoom(queries, found.id);
}

let activeVerifications = 0;
async function verifyBounded(proof: SemaphoreProof) {
  if (activeVerifications >= 1)
    throw new HttpError(429, 'PROOF_BUSY', 'Proof checks are busy. Wait a moment and try again.');
  activeVerifications += 1;
  try {
    return await verifyProof(proof);
  } finally {
    activeVerifications -= 1;
  }
}

function validInviteToken(token: string) {
  try {
    const bytes = Buffer.from(token, 'base64url');
    return bytes.length === 32 && bytes.toString('base64url') === token;
  } catch {
    return false;
  }
}

async function currentGroup(queries: Queries, roomIdValue: string) {
  const rows = await queries.query<{ commitment: string }>(
    'SELECT commitment FROM room_proof_commitments WHERE room_id = $1 ORDER BY created_at, commitment LIMIT 1000',
    [roomIdValue],
  );
  const commitments = rows.map((row) => row.commitment);
  return { commitments, group: new Group(commitments.map(BigInt)) };
}

export function proofAdmissionRoutes(database: Database) {
  const router = Router();

  router.get('/rooms/:id/enrollments', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [room] = await database.query<{ id: string; owner_id: string; status: string; expires_at: Date; admission_policy: string }>(
      'SELECT id, owner_id, status, expires_at, admission_policy FROM rooms WHERE id = $1', [id],
    );
    requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    requireOwner(room, request.session!.id);
    requireCondition(room.admission_policy === 'proof', 409, 'PROOF_POLICY_REQUIRED', 'This room does not use workshop proof admission.');
    const rows = await database.query<InviteRow>(
      `SELECT id, invite_number, created_at, revoked_at, enrolled_commitment
       FROM room_proof_invites WHERE room_id = $1 ORDER BY invite_number LIMIT 1000`, [id],
    );
    const counts = rows.reduce((result, row) => {
      if (row.revoked_at) result.revoked += 1;
      else if (row.enrolled_commitment) result.enrolled += 1;
      else result.available += 1;
      return result;
    }, { enrolled: 0, available: 0, revoked: 0 });
    const terminal = room.status === 'closed' || room.expires_at <= (await clock(database));
    response.json({ enrollments: rows.map((row) => inviteView(row, terminal)), counts });
  });

  router.post('/rooms/:id/enrollments', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { count } = issueInput.parse(request.body);
    const invites = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireActive(room);
      requireCondition(room.admission_policy === 'proof', 409, 'PROOF_POLICY_REQUIRED', 'This room does not use workshop proof admission.');
      const [used] = await transaction.query<{ total: number; next: number }>(
        `SELECT count(*)::int AS total, (COALESCE(max(invite_number), 0) + 1)::int AS next
         FROM room_proof_invites WHERE room_id = $1`, [id],
      );
      requireCondition(used.total + count <= 1000, 409, 'ENROLLMENT_LIMIT', 'This room has reached its limit of 1,000 enrollment links.');
      const issued: Array<ReturnType<typeof inviteView> & { token: string }> = [];
      for (let offset = 0; offset < count; offset += 1) {
        const token = randomBytes(32).toString('base64url');
        const [row] = await transaction.query<InviteRow>(
          `INSERT INTO room_proof_invites (id, room_id, invite_number, token_digest)
           VALUES ($1, $2, $3, $4)
           RETURNING id, invite_number, created_at, revoked_at, enrolled_commitment`,
          [randomUUID(), id, used.next + offset, digest(token)],
        );
        issued.push({ ...inviteView(row, false), token });
      }
      await recordActivity(transaction, id, 'proof_enrollments_issued');
      return issued;
    });
    response.status(201).json({ enrollments: invites });
  });

  router.patch('/rooms/:id/enrollments/:inviteId', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const inviteId = roomId.parse(request.params.inviteId);
    revokeInput.parse(request.body);
    const invite = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireActive(room);
      requireCondition(room.admission_policy === 'proof', 409, 'PROOF_POLICY_REQUIRED', 'This room does not use workshop proof admission.');
      const [current] = await transaction.query<InviteRow>(
        `SELECT id, invite_number, created_at, revoked_at, enrolled_commitment
         FROM room_proof_invites WHERE id = $1 AND room_id = $2 FOR UPDATE`, [inviteId, id],
      );
      requireCondition(current, 404, 'ENROLLMENT_NOT_FOUND', 'Enrollment link not found.');
      requireCondition(!current.enrolled_commitment, 409, 'ENROLLMENT_ALREADY_USED', 'This enrollment link has already saved a credential. Remove participant access from the participant list instead.');
      if (!current.revoked_at) {
        const [updated] = await transaction.query<InviteRow>(
          `UPDATE room_proof_invites SET revoked_at = clock_timestamp() WHERE id = $1
           RETURNING id, invite_number, created_at, revoked_at, enrolled_commitment`, [inviteId],
        );
        await recordActivity(transaction, id, 'proof_enrollment_revoked');
        return updated;
      }
      return current;
    });
    response.json(inviteView(invite, false));
  });

  router.post('/join/:code/enroll', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const input = enrollInput.parse(request.body);
    if (!validInviteToken(input.token)) inviteError();
    const result = await database.transaction(async (transaction) => {
      const room = await lockRoomByCode(transaction, code);
      requireOpen(room);
      requireCondition(room.admission_policy === 'proof', 409, 'PROOF_POLICY_REQUIRED', 'This room does not use workshop proof admission.');
      requireCondition(room.owner_id !== request.session!.id, 409, 'ALREADY_OWNER', 'You already organize this room.');
      const [invite] = await transaction.query<InviteRow>(
        `SELECT id, invite_number, created_at, revoked_at, enrolled_commitment
         FROM room_proof_invites WHERE room_id = $1 AND token_digest = $2 FOR UPDATE`,
        [room.id, digest(input.token)],
      );
      if (!invite || invite.revoked_at) inviteError();
      if (invite.enrolled_commitment === input.commitment) return { enrolled: true, alreadyEnrolled: true };
      if (invite.enrolled_commitment) inviteError();
      const [existing] = await transaction.query<{ commitment: string }>(
        'SELECT commitment FROM room_proof_commitments WHERE room_id = $1 AND commitment = $2',
        [room.id, input.commitment],
      );
      if (existing) inviteError();
      const [count] = await transaction.query<{ total: number }>(
        'SELECT count(*)::int AS total FROM room_proof_commitments WHERE room_id = $1', [room.id],
      );
      requireCondition(count.total < 1000, 409, 'PROOF_GROUP_FULL', 'This workshop has reached its 1,000 credential limit.');
      await transaction.query(
        'INSERT INTO room_proof_commitments (room_id, commitment, invite_id) VALUES ($1, $2, $3)',
        [room.id, input.commitment, invite.id],
      );
      await transaction.query('UPDATE room_proof_invites SET enrolled_commitment = $2 WHERE id = $1', [invite.id, input.commitment]);
      return { enrolled: true, alreadyEnrolled: false };
    });
    response.json(result);
  });

  router.post('/join/:code/proof-challenge', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    z.object({}).strict().parse(request.body ?? {});
    const challenge = await database.transaction(async (transaction) => {
      const room = await lockRoomByCode(transaction, code);
      requireOpen(room);
      requireCondition(room.admission_policy === 'proof', 409, 'PROOF_POLICY_REQUIRED', 'This room does not use workshop proof admission.');
      requireCondition(room.owner_id !== request.session!.id, 409, 'ALREADY_OWNER', 'You already organize this room.');
      const [existing] = await transaction.query<{ status: string }>(
        'SELECT status FROM memberships WHERE room_id = $1 AND session_id = $2', [room.id, request.session!.id],
      );
      requireCondition(!existing || !['revoked', 'denied'].includes(existing.status), 403, 'ADMISSION_DENIED', 'The organizer has declined access for this browser.');
      requireCondition(existing?.status !== 'approved', 409, 'ALREADY_ADMITTED', 'This browser already has workshop access.');
      const { commitments, group } = await currentGroup(transaction, room.id);
      const [previous] = await transaction.query<{ id: string }>(
        'SELECT id FROM room_proof_challenges WHERE room_id = $1 AND session_id = $2 FOR UPDATE',
        [room.id, request.session!.id],
      );
      const id = previous?.id ?? randomUUID();
      const nonce = randomBytes(32).toString('base64url');
      const scope = workshopScope(room.id);
      const message = workshopMessage({
        challengeId: id,
        nonce,
        roomId: room.id,
        sessionId: request.session!.id,
        root: group.root.toString(),
      });
      const [stored] = await transaction.query<{ id: string; expires_at: Date }>(
        `INSERT INTO room_proof_challenges (id, room_id, session_id, accepted_root, scope, message, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, LEAST(clock_timestamp() + interval '2 minutes', $7::timestamptz))
         ON CONFLICT (room_id, session_id) DO UPDATE SET
           accepted_root = EXCLUDED.accepted_root, scope = EXCLUDED.scope,
           message = EXCLUDED.message, expires_at = EXCLUDED.expires_at, consumed_at = NULL
         RETURNING id, expires_at`,
        [id, room.id, request.session!.id, group.root.toString(), scope, message, request.session!.expiresAt],
      );
      return {
        challengeId: stored.id,
        version: WORKSHOP_PROOF_VERSION,
        depth: WORKSHOP_PROOF_DEPTH,
        root: group.root.toString(),
        scope,
        message,
        commitments,
        expiresAt: stored.expires_at.toISOString(),
      };
    });
    try {
      await database.transaction(async (transaction) => {
        await transaction.query(
          `WITH expired AS (
             SELECT id FROM room_proof_challenges WHERE expires_at < clock_timestamp()
             ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 100
           )
           DELETE FROM room_proof_challenges c USING expired e
           WHERE c.id = e.id AND c.expires_at < clock_timestamp()`,
        );
      });
    } catch {
      // Expired rows are harmless; later challenge requests retry this bounded cleanup.
    }
    response.json(challenge);
  });

  router.post('/join/:code/prove', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const input = proveInput.parse(request.body);
    const label = input.label ?? 'Workshop attendee';
    const [challenge] = await database.query<{
      id: string; room_id: string; session_id: string; accepted_root: string; scope: string;
      message: string; expires_at: Date; consumed_at: Date | null;
    }>(
      `SELECT c.id, c.room_id, c.session_id, c.accepted_root, c.scope, c.message,
         c.expires_at, c.consumed_at
       FROM room_proof_challenges c JOIN rooms r ON r.id = c.room_id
       WHERE c.id = $1 AND r.join_code = $2`, [input.challengeId, code],
    );
    if (!challenge || challenge.session_id !== request.session!.id || challenge.expires_at <= (await clock(database))) proofError();
    const roomState = await database.query<{ owner_id: string; status: string; expires_at: Date; admission_policy: string }>(
      'SELECT owner_id, status, expires_at, admission_policy FROM rooms WHERE id = $1', [challenge.room_id],
    );
    const state = roomState[0];
    if (!state || state.owner_id === request.session!.id || state.status !== 'open' || state.expires_at <= (await clock(database)) || state.admission_policy !== 'proof') proofError();
    const [membership] = await database.query<{ status: string }>(
      'SELECT status FROM memberships WHERE room_id = $1 AND session_id = $2', [challenge.room_id, request.session!.id],
    );
    requireCondition(!membership || !['revoked', 'denied'].includes(membership.status), 403, 'ADMISSION_DENIED', 'The organizer has declined access for this browser.');
    const proof = input.proof;
    if (
      proof.merkleTreeDepth !== WORKSHOP_PROOF_DEPTH ||
      proof.merkleTreeRoot !== challenge.accepted_root ||
      proof.scope !== challenge.scope ||
      proof.message !== challenge.message ||
      challenge.scope !== workshopScope(challenge.room_id)
    ) proofError();

    let valid = false;
    try {
      valid = await verifyBounded(proof);
    } catch (error) {
      if (error instanceof HttpError && error.status === 429) throw error;
      proofError();
    }
    if (!valid) proofError();

    const member = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, challenge.room_id);
      requireOpen(room);
      requireCondition(room.join_code === code && room.admission_policy === 'proof', 403, 'WORKSHOP_PROOF_INVALID', 'This membership proof is invalid or no longer available. Refresh and try again.');
      requireCondition(room.owner_id !== request.session!.id, 409, 'ALREADY_OWNER', 'You already organize this room.');
      const [current] = await transaction.query<typeof challenge>(
        `SELECT id, room_id, session_id, accepted_root, scope, message, expires_at, consumed_at
         FROM room_proof_challenges WHERE id = $1 AND room_id = $2 FOR UPDATE`,
        [input.challengeId, room.id],
      );
      if (!current || current.session_id !== request.session!.id || current.expires_at <= (await clock(transaction)) ||
          current.accepted_root !== proof.merkleTreeRoot || current.scope !== proof.scope || current.message !== proof.message)
        proofError();
      const [existing] = await transaction.query<{ id: string; label: string; status: string }>(
        'SELECT id, label, status FROM memberships WHERE room_id = $1 AND session_id = $2 FOR UPDATE',
        [room.id, request.session!.id],
      );
      requireCondition(!existing || !['revoked', 'denied'].includes(existing.status), 403, 'ADMISSION_DENIED', 'The organizer has declined access for this browser.');
      const [consumed] = await transaction.query<{ session_id: string | null; challenge_id: string | null }>(
        `SELECT session_id, challenge_id FROM room_proof_nullifiers WHERE room_id = $1 AND nullifier = $2 FOR UPDATE`,
        [room.id, proof.nullifier],
      );
      if (consumed) {
        if (consumed.session_id === request.session!.id && consumed.challenge_id === input.challengeId &&
            current.consumed_at && existing?.status === 'approved') {
          admissionFix(input, geoOf(room));
          return existing;
        }
        proofError();
      }
      if (current.consumed_at || existing?.status === 'approved') proofError();
      const fix = admissionFix(input, geoOf(room));
      const [session] = await transaction.query<{ expires_at: Date }>(
        'SELECT expires_at FROM sessions WHERE id = $1 FOR UPDATE', [request.session!.id],
      );
      requireCondition(session && session.expires_at > (await clock(transaction)), 401, 'SESSION_EXPIRED', 'Your browser session has expired. Reload the page and try again.');
      const [approved] = await transaction.query<{ id: string; label: string; status: string }>(
        `INSERT INTO memberships (id, room_id, session_id, label, status, decided_at,
           last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at)
         VALUES ($1, $2, $3, $4, 'approved', clock_timestamp(), $5, $6, $7, $8, $9,
           CASE WHEN $9::boolean IS NULL THEN NULL ELSE clock_timestamp() END)
         ON CONFLICT (room_id, session_id) DO UPDATE SET label = EXCLUDED.label,
           status = 'approved', decided_at = clock_timestamp(), last_lat = EXCLUDED.last_lat,
           last_lng = EXCLUDED.last_lng, last_accuracy_m = EXCLUDED.last_accuracy_m,
           last_distance_m = EXCLUDED.last_distance_m, last_inside = EXCLUDED.last_inside,
           last_checked_at = EXCLUDED.last_checked_at
         RETURNING id, label, status`,
        [randomUUID(), room.id, request.session!.id, label, fix?.lat ?? null, fix?.lng ?? null,
          fix?.accuracyM ?? null, fix?.distanceM ?? null, fix?.inside ?? null],
      );
      await transaction.query(
        `INSERT INTO room_proof_nullifiers (room_id, nullifier, session_id, challenge_id)
         VALUES ($1, $2, $3, $4)`, [room.id, proof.nullifier, request.session!.id, input.challengeId],
      );
      await transaction.query('UPDATE room_proof_challenges SET consumed_at = clock_timestamp() WHERE id = $1', [input.challengeId]);
      await recordActivity(transaction, room.id, 'proof_admitted', approved.label);
      return approved;
    });
    response.json(member);
  });

  return router;
}
