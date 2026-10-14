import { randomBytes, randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import {
  joinCode,
  memberDecision,
  roomId,
  roomInput,
  roomTemplateInput,
  type Room,
  type RoomInput,
  type PublicRoom,
  type Member,
} from '../shared/rooms.js';
import type { Database, Queries } from './database.js';
import { requireCondition } from './errors.js';
import { activityQuery, readActivity, recordActivity } from './activity.js';
import type { ActivityKind, RoomField } from '../shared/activity.js';

interface RoomRow {
  id: string;
  owner_id: string;
  join_code: string;
  title: string;
  description: string;
  status: 'draft' | 'open' | 'closed';
  expires_at: Date;
  created_at: Date;
  is_expired: boolean;
  membership_status: Room['membershipStatus'];
}

type MembershipRow = Omit<Member, 'requestedAt'> & { requestedAt: Date };

const selection = `SELECT r.*, r.expires_at <= clock_timestamp() AS is_expired,
  m.status AS membership_status FROM rooms r
  LEFT JOIN memberships m ON m.room_id = r.id AND m.session_id = $1`;

function roomView(row: RoomRow, sessionId: string): Room {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status: row.status === 'closed' ? 'closed' : row.is_expired ? 'expired' : row.status,
    expiresAt: row.expires_at.toISOString(),
    createdAt: row.created_at.toISOString(),
    joinCode: row.join_code,
    role: row.owner_id === sessionId ? 'owner' : 'participant',
    membershipStatus: row.membership_status ?? null,
  };
}

async function clock(queries: Queries) {
  const [row] = await queries.query<{ now: Date }>('SELECT clock_timestamp() AS now');
  return row.now;
}

async function lockRoom(queries: Queries, id: string) {
  const [row] = await queries.query<RoomRow>('SELECT * FROM rooms WHERE id = $1 FOR UPDATE', [id]);
  requireCondition(row, 404, 'ROOM_NOT_FOUND', 'Room not found.');
  row.is_expired = row.expires_at <= (await clock(queries));
  return row;
}

function requireOwner(row: RoomRow, sessionId: string) {
  requireCondition(
    row.owner_id === sessionId,
    403,
    'OWNER_REQUIRED',
    'Only the organizer can do this.',
  );
}

function requireActive(row: RoomRow) {
  requireCondition(
    row.status !== 'closed' && !row.is_expired,
    410,
    'ROOM_CLOSED',
    'This room has closed.',
  );
}

function requireOpen(row: RoomRow) {
  requireActive(row);
  requireCondition(row.status === 'open', 409, 'ROOM_NOT_OPEN', 'This room is not open yet.');
}

function validateExpiry(value: string, now: Date, sessionExpiry: Date) {
  const expiresAt = new Date(value);
  requireCondition(expiresAt > now, 422, 'INVALID_EXPIRY', 'Choose an expiry time in the future.');
  requireCondition(
    expiresAt.getTime() - now.getTime() <= 7 * 24 * 60 * 60 * 1000,
    422,
    'INVALID_EXPIRY',
    'A room can remain available for up to seven days.',
  );
  requireCondition(
    expiresAt < sessionExpiry,
    422,
    'SESSION_TOO_SHORT',
    'Room expiry must be before your browser session expires.',
  );
  return expiresAt;
}

async function insertRoom(
  queries: Queries,
  ownerId: string,
  sessionExpiry: Date,
  input: RoomInput,
  kind: Extract<ActivityKind, 'room_created' | 'room_duplicated'> = 'room_created',
) {
  const expiresAt = validateExpiry(input.expiresAt, await clock(queries), sessionExpiry);
  const [row] = await queries.query<RoomRow>(
    `INSERT INTO rooms (id, owner_id, join_code, title, description, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *, false AS is_expired`,
    [
      randomUUID(),
      ownerId,
      randomBytes(12).toString('base64url'),
      input.title,
      input.description,
      expiresAt,
    ],
  );
  await recordActivity(queries, row.id, kind);
  return roomView(row, ownerId);
}

export function roomRoutes(database: Database) {
  const router = Router();

  router.get('/rooms', async (request, response) => {
    const sessionId = request.session!.id;
    const rows = await database.query<RoomRow>(
      `${selection}
      WHERE r.owner_id = $1 OR m.session_id = $1 ORDER BY r.created_at DESC`,
      [sessionId],
    );
    response.json(rows.map((row) => roomView(row, sessionId)));
  });

  router.post('/rooms', async (request, response) => {
    const input = roomInput.parse(request.body);
    response
      .status(201)
      .json(
        await database.transaction((transaction) =>
          insertRoom(transaction, request.session!.id, request.session!.expiresAt, input),
        ),
      );
  });

  router.post('/rooms/:id/duplicate', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = roomTemplateInput.parse(request.body);
    const room = await database.transaction(async (transaction) => {
      const original = await lockRoom(transaction, id);
      requireOwner(original, request.session!.id);
      return insertRoom(
        transaction,
        request.session!.id,
        request.session!.expiresAt,
        {
          title: input.title ?? original.title,
          description: input.description ?? original.description,
          expiresAt: input.expiresAt,
        },
        'room_duplicated',
      );
    });
    response.status(201).json(room);
  });

  router.get('/join/:code', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const [row] = await database.query<RoomRow>(`${selection} WHERE r.join_code = $2`, [
      request.session!.id,
      code,
    ]);
    requireCondition(row, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    const view = roomView(row, request.session!.id);
    const publicRoom: PublicRoom = {
      id: view.id,
      title: view.title,
      description: view.description,
      status: view.status,
      expiresAt: view.expiresAt,
      membershipStatus: view.membershipStatus,
      isOwner: view.role === 'owner',
      organizerKeyFingerprint: null,
      organizerPublicKey: null,
    };
    const [recipientKey] = await database.query<{ publicKey: Buffer; fingerprint: string }>(
      'SELECT public_key AS "publicKey", fingerprint FROM room_recipient_keys WHERE room_id = $1', [view.id]
    );
    response.json({ ...publicRoom, organizerKeyFingerprint: recipientKey?.fingerprint ?? null,
      organizerPublicKey: recipientKey?.publicKey.toString('base64') ?? null });
  });

  router.post('/join/:code', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const { label } = z
      .object({ label: z.string().trim().min(1).max(50) })
      .strict()
      .parse(request.body);
    const membership = await database.transaction(async (transaction) => {
      const [found] = await transaction.query<{ id: string }>(
        'SELECT id FROM rooms WHERE join_code = $1',
        [code],
      );
      requireCondition(found, 404, 'ROOM_NOT_FOUND', 'Room not found.');
      const row = await lockRoom(transaction, found.id);
      requireOpen(row);
      requireCondition(
        row.owner_id !== request.session!.id,
        409,
        'ALREADY_OWNER',
        'You already organize this room.',
      );
      const [existing] = await transaction.query<MembershipRow>(
        'SELECT id, label, status, requested_at AS "requestedAt" FROM memberships WHERE room_id = $1 AND session_id = $2',
        [row.id, request.session!.id],
      );
      requireCondition(
        !existing || !['revoked', 'denied'].includes(existing.status),
        403,
        'ADMISSION_DENIED',
        'The organizer has declined access for this browser.',
      );
      if (existing) return existing;
      const [member] = await transaction.query<MembershipRow>(
        `INSERT INTO memberships (id, room_id, session_id, label) VALUES ($1, $2, $3, $4)
         RETURNING id, label, status, requested_at AS "requestedAt"`,
        [randomUUID(), row.id, request.session!.id, label],
      );
      await recordActivity(transaction, row.id, 'join_requested', member.label);
      return member;
    });
    response.status(200).json(membership);
  });

  router.get('/rooms/:id', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [row] = await database.query<RoomRow>(`${selection} WHERE r.id = $2`, [
      request.session!.id,
      id,
    ]);
    requireCondition(row, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    if (row.owner_id !== request.session!.id) {
      requireCondition(
        row.membership_status === 'approved',
        403,
        'ADMISSION_REQUIRED',
        'Organizer approval is required.',
      );
      requireOpen(row);
    }
    response.json(roomView(row, request.session!.id));
  });

  router.patch('/rooms/:id', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = roomInput.parse(request.body);
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireActive(room);
      const expiresAt = validateExpiry(
        input.expiresAt,
        await clock(transaction),
        request.session!.expiresAt,
      );
      const [updated] = await transaction.query<RoomRow>(
        `UPDATE rooms SET title = $2, description = $3, expires_at = $4
         WHERE id = $1 RETURNING *, false AS is_expired`,
        [id, input.title, input.description, expiresAt],
      );
      const changedFields: RoomField[] = [];
      if (room.title !== input.title) changedFields.push('title');
      if (room.description !== input.description) changedFields.push('description');
      if (room.expires_at.getTime() !== expiresAt.getTime()) changedFields.push('expiresAt');
      if (changedFields.length)
        await recordActivity(transaction, id, 'room_updated', null, changedFields);
      return updated;
    });
    response.json(roomView(row, request.session!.id));
  });

  for (const action of ['open', 'close'] as const) {
    router.post(`/rooms/:id/${action}`, async (request, response) => {
      const id = roomId.parse(request.params.id);
      const row = await database.transaction(async (transaction) => {
        const room = await lockRoom(transaction, id);
        requireOwner(room, request.session!.id);
        requireActive(room);
        if (action === 'open')
          requireCondition(
            room.status === 'draft',
            409,
            'INVALID_TRANSITION',
            'Only a draft room can be opened.',
          );
        const [updated] = await transaction.query<RoomRow>(
          `UPDATE rooms SET status = $2::varchar, closed_at = CASE WHEN $2::varchar = 'closed' THEN clock_timestamp() ELSE NULL END
           WHERE id = $1 RETURNING *, false AS is_expired`,
          [id, action === 'open' ? 'open' : 'closed'],
        );
        await recordActivity(transaction, id, action === 'open' ? 'room_opened' : 'room_closed');
        return updated;
      });
      response.json(roomView(row, request.session!.id));
    });
  }

  router.get('/rooms/:id/activity', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { before } = activityQuery.parse(request.query);
    const [room] = await database.query<RoomRow>('SELECT * FROM rooms WHERE id = $1', [id]);
    requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    requireOwner(room, request.session!.id);
    response.json(await readActivity(database, id, before));
  });

  router.get('/rooms/:id/members', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [room] = await database.query<RoomRow>('SELECT * FROM rooms WHERE id = $1', [id]);
    requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    requireOwner(room, request.session!.id);
    const rows = await database.query(
      `SELECT m.id, m.label, m.status, m.requested_at AS "requestedAt"
       FROM memberships m JOIN sessions s ON s.id = m.session_id
       WHERE m.room_id = $1 AND s.expires_at > clock_timestamp() ORDER BY m.requested_at`,
      [id],
    );
    response.json(rows);
  });

  router.patch('/rooms/:id/members/:memberId', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const memberId = roomId.parse(request.params.memberId);
    const { status } = memberDecision.parse(request.body);
    const member = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireOpen(room);
      const [current] = await transaction.query<{ status: string }>(
        `SELECT m.status FROM memberships m JOIN sessions s ON s.id = m.session_id
         WHERE m.id = $1 AND m.room_id = $2 AND s.expires_at > clock_timestamp()`,
        [memberId, id],
      );
      requireCondition(current, 404, 'MEMBER_NOT_FOUND', 'Join request not found.');
      const allowed =
        status === 'revoked' ? current.status === 'approved' : current.status === 'pending';
      requireCondition(
        allowed,
        409,
        'INVALID_TRANSITION',
        'This membership cannot make that transition.',
      );
      const [updated] = await transaction.query<{ label: string }>(
        `UPDATE memberships SET status = $2, decided_at = clock_timestamp()
         WHERE id = $1 RETURNING id, label, status, requested_at AS "requestedAt"`,
        [memberId, status],
      );
      await recordActivity(transaction, id, `member_${status}`, updated.label);
      return updated;
    });
    response.json(member);
  });

  return router;
}
