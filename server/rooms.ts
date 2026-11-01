import { randomBytes, randomUUID } from 'node:crypto';
import { Router } from 'express';
import {
  geoAreaInput,
  joinCode,
  joinRequest,
  memberDecision,
  maxEntryAccuracyM,
  placeQuery,
  positionReport,
  roomCreateInput,
  roomId,
  roomInput,
  roomTemplateInput,
  type GeoRule,
  type Room,
  type RoomCreateInput,
  type PublicRoom,
} from '../shared/rooms.js';
import { credentialRequirement, type CredentialRule } from '../shared/credentials.js';
import { haversineMeters, locationAccuracyMessage } from '../shared/geo.js';
import type { Database, Queries } from './database.js';
import { HttpError, requireCondition } from './errors.js';
import { credentialIssuer, verifyCredentialProof } from './zk.js';
import type { Geocoder } from './geocoding.js';
import { requireParticipantAccess } from './participantAccess.js';
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
  geo_lat: number | null;
  geo_lng: number | null;
  geo_radius_m: number | null;
  geo_label: string | null;
  credential_dept: number | null;
  credential_year: number | null;
  credential_issuer_ax: string | null;
  credential_issuer_ay: string | null;
  is_expired: boolean;
  membership_status: Room['membershipStatus'];
}

interface MemberRow {
  id: string;
  label: string;
  status: string;
  requestedAt: string;
  last_lat: number | null;
  last_lng: number | null;
  last_accuracy_m: number | null;
  last_distance_m: number | null;
  last_inside: boolean | null;
  last_checked_at: Date | null;
  credential_verified_at: Date | null;
}

const selection = `SELECT r.*, r.expires_at <= clock_timestamp() AS is_expired,
  m.status AS membership_status FROM rooms r
  LEFT JOIN memberships m ON m.room_id = r.id AND m.session_id = $1`;

function geoOf(row: RoomRow): GeoRule | null {
  if (row.geo_lat == null || row.geo_lng == null || row.geo_radius_m == null) return null;
  return { lat: row.geo_lat, lng: row.geo_lng, radiusM: row.geo_radius_m };
}

function credentialOf(row: RoomRow): CredentialRule | null {
  if (
    row.credential_dept == null ||
    row.credential_year == null ||
    row.credential_issuer_ax == null ||
    row.credential_issuer_ay == null
  ) {
    return null;
  }
  return {
    dept: row.credential_dept,
    year: row.credential_year,
    issuer: { ax: row.credential_issuer_ax, ay: row.credential_issuer_ay },
  };
}

function isCredentialReuse(error: unknown) {
  if (typeof error !== 'object' || error === null) return false;
  const code = (error as { code?: unknown }).code;
  if (code !== '23505') return false;
  const constraint = (error as { constraint?: unknown }).constraint;
  const text = `${typeof constraint === 'string' ? constraint : ''} ${error instanceof Error ? error.message : ''}`;
  return text.includes('credential_nullifier');
}

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
    geo: geoOf(row),
    geoLabel: row.geo_label,
    credential: credentialOf(row),
  };
}

function publicView(
  row: RoomRow,
  sessionId: string,
  key: { fingerprint: string; publicKey: string } | null,
): PublicRoom {
  const view = roomView(row, sessionId);
  return {
    id: view.id,
    title: view.title,
    description: view.description,
    status: view.status,
    expiresAt: view.expiresAt,
    membershipStatus: view.membershipStatus,
    isOwner: view.role === 'owner',
    organizerKeyFingerprint: key?.fingerprint ?? null,
    organizerPublicKey: key?.publicKey ?? null,
    geo: view.geo,
    geoLabel: view.geoLabel,
    credential: view.credential,
    needsLocation:
      view.geo != null && view.role !== 'owner' && view.membershipStatus !== 'approved',
  };
}

function memberView(row: MemberRow) {
  return {
    id: row.id,
    label: row.label,
    status: row.status,
    requestedAt: row.requestedAt,
    inside: row.last_inside,
    distanceM:
      row.last_distance_m == null ? null : Math.round((row.last_distance_m as number) * 10) / 10,
    accuracyM:
      row.last_accuracy_m == null ? null : Math.round((row.last_accuracy_m as number) * 10) / 10,
    checkedAt: row.last_checked_at ? (row.last_checked_at as Date).toISOString() : null,
    credentialVerified: row.credential_verified_at != null,
  };
}

const FIX_FRESH_MS = 60 * 1000;

function validateFix(input: { lat: number; lng: number; accuracyM: number; timestamp: string }) {
  requireCondition(
    input.accuracyM <= maxEntryAccuracyM,
    422,
    'GEO_INACCURATE',
    locationAccuracyMessage(input.accuracyM, maxEntryAccuracyM),
  );
  const age = Date.now() - new Date(input.timestamp).getTime();
  requireCondition(
    Number.isFinite(age) && age >= -30 * 1000 && age <= FIX_FRESH_MS,
    422,
    'GEO_STALE',
    'Location reading is stale. Share a fresh location.',
  );
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

// The area may be adjusted until somebody has been admitted under it. After
// that the fence is fixed, so an admitted participant is never re-scoped out
// of the room they were approved for.
async function requireNoAdmissions(queries: Queries, id: string) {
  const [approved] = await queries.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM memberships WHERE room_id = $1 AND status IN ('approved', 'revoked')",
    [id],
  );
  requireCondition(
    approved.count === 0,
    409,
    'INVALID_TRANSITION',
    'Room admission rules are fixed once a participant has been admitted.',
  );
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
  input: RoomCreateInput,
  kind: Extract<ActivityKind, 'room_created' | 'room_duplicated'> = 'room_created',
) {
  const expiresAt = validateExpiry(input.expiresAt, await clock(queries), sessionExpiry);
  const issuer = input.credential ? credentialIssuer() : null;
  const [row] = await queries.query<RoomRow>(
    `INSERT INTO rooms (id, owner_id, join_code, title, description, expires_at,
       credential_dept, credential_year, credential_issuer_ax, credential_issuer_ay)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *, false AS is_expired`,
    [
      randomUUID(),
      ownerId,
      randomBytes(12).toString('base64url'),
      input.title,
      input.description,
      expiresAt,
      input.credential?.dept ?? null,
      input.credential?.year ?? null,
      issuer?.ax ?? null,
      issuer?.ay ?? null,
    ],
  );
  await recordActivity(queries, row.id, kind);
  return roomView(row, ownerId);
}

export function roomRoutes(database: Database, geocoder: Geocoder) {
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
    const input = roomCreateInput.parse(request.body);
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
          credential: input.credential ?? null,
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
    const [recipientKey] = await database.query<{ publicKey: Buffer; fingerprint: string }>(
      'SELECT public_key AS "publicKey", fingerprint FROM room_recipient_keys WHERE room_id = $1',
      [row.id],
    );
    response.json(
      publicView(
        row,
        request.session!.id,
        recipientKey
          ? {
              fingerprint: recipientKey.fingerprint,
              publicKey: Buffer.from(recipientKey.publicKey).toString('base64'),
            }
          : null,
      ),
    );
  });

  router.get('/geo/search', async (request, response) => {
    const { q } = placeQuery.parse(request.query);
    response.json({ results: await geocoder.search(q) });
  });

  router.post('/rooms/:id/geo', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = geoAreaInput.parse(request.body);
    const [existing] = await database.query<RoomRow>('SELECT * FROM rooms WHERE id = $1', [id]);
    requireCondition(existing, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    requireOwner(existing, request.session!.id);
    const label = input.label ?? (await geocoder.reverse(input.lat, input.lng));
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireActive(room);
      await requireNoAdmissions(transaction, id);
      const [updated] = await transaction.query<RoomRow>(
        `UPDATE rooms SET geo_lat = $2, geo_lng = $3, geo_radius_m = $4, geo_label = $5,
           geo_source = $6
         WHERE id = $1 RETURNING *, false AS is_expired`,
        [id, input.lat, input.lng, input.radiusM, label, input.source ?? null],
      );
      return updated;
    });
    response.json(roomView(row, request.session!.id));
  });

  router.delete('/rooms/:id/geo', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireActive(room);
      await requireNoAdmissions(transaction, id);
      const [updated] = await transaction.query<RoomRow>(
        `UPDATE rooms SET geo_lat = NULL, geo_lng = NULL, geo_radius_m = NULL,
           geo_label = NULL, geo_source = NULL
         WHERE id = $1 RETURNING *, false AS is_expired`,
        [id],
      );
      return updated;
    });
    response.json(roomView(row, request.session!.id));
  });

  for (const method of ['put', 'delete'] as const) {
    router[method]('/rooms/:id/credential', async (request, response) => {
      const id = roomId.parse(request.params.id);
      const input = method === 'put' ? credentialRequirement.parse(request.body) : null;
      const issuer = credentialIssuer();
      const row = await database.transaction(async (transaction) => {
        const room = await lockRoom(transaction, id);
        requireOwner(room, request.session!.id);
        requireActive(room);
        await requireNoAdmissions(transaction, id);
        const before = credentialOf(room);
        const [updated] = await transaction.query<RoomRow>(
          `UPDATE rooms SET credential_dept = $2, credential_year = $3,
             credential_issuer_ax = $4, credential_issuer_ay = $5
           WHERE id = $1 RETURNING *, false AS is_expired`,
          [
            id,
            input?.dept ?? null,
            input?.year ?? null,
            input ? issuer.ax : null,
            input ? issuer.ay : null,
          ],
        );
        const changedCredential =
          (before === null) !== (input === null) ||
          (before !== null &&
            input !== null &&
            (before.dept !== input.dept || before.year !== input.year));
        if (changedCredential)
          await recordActivity(transaction, id, 'room_updated', null, ['credential']);
        return updated;
      });
      response.json(roomView(row, request.session!.id));
    });
  }

  router.post('/join/:code/challenge', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const [room] = await database.query<RoomRow>('SELECT * FROM rooms WHERE join_code = $1', [code]);
    requireCondition(room, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    requireOpen({ ...room, is_expired: room.expires_at <= await clock(database) });
    const challenge = BigInt(`0x${randomBytes(31).toString('hex')}`).toString();
    const [row] = await database.query<{ expires_at: Date }>(
      `INSERT INTO credential_challenges(room_id, session_id, challenge, expires_at)
       VALUES ($1, $2, $3, clock_timestamp() + interval '10 minutes')
       ON CONFLICT(room_id, session_id) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at
       RETURNING expires_at`, [room.id, request.session!.id, challenge]);
    response.json({ challenge, expiresAt: row.expires_at.toISOString() });
  });

  router.post('/join/:code', async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const input = joinRequest.parse(request.body);
    const [found] = await database.query<RoomRow>('SELECT * FROM rooms WHERE join_code = $1', [
      code,
    ]);
    requireCondition(found, 404, 'ROOM_NOT_FOUND', 'Room not found.');
    // Verify before opening the transaction: a pairing check takes a few hundred
    // milliseconds and must not hold the room lock.
    const requirement = credentialOf(found);
    let verified: { nullifier: string; challenge: string; validUntil: number } | null = null;
    if (requirement) {
      requireCondition(
        input.credentialProof != null,
        403,
        'CREDENTIAL_REQUIRED',
        'This room requires a zero-knowledge proof of your institution credential.',
      );
      verified = await verifyCredentialProof(input.credentialProof, found.id, requirement);
    }
    const membership = await database.transaction(async (transaction) => {
      const row = await lockRoom(transaction, found.id);
      requireOpen(row);
      requireCondition(
        row.owner_id !== request.session!.id,
        409,
        'ALREADY_OWNER',
        'You already organize this room.',
      );
      const currentRule = credentialOf(row);
      requireCondition(
        (currentRule === null) === (requirement === null) &&
          (requirement === null ||
            (currentRule!.dept === requirement.dept &&
              currentRule!.year === requirement.year &&
              currentRule!.issuer.ax === requirement.issuer.ax &&
              currentRule!.issuer.ay === requirement.issuer.ay)),
        409,
        'INVALID_TRANSITION',
        'This room’s credential requirement changed. Request access again.',
      );
      if (verified) {
        const [challenge] = await transaction.query<{ challenge: string }>(
          `SELECT challenge FROM credential_challenges WHERE room_id = $1 AND session_id = $2
           AND expires_at > clock_timestamp() FOR UPDATE`, [row.id, request.session!.id]);
        requireCondition(challenge?.challenge === verified.challenge, 422, 'CREDENTIAL_CHALLENGE_INVALID', 'Generate a fresh proof in this browser.');
        requireCondition(verified.validUntil * 1000 > (await clock(transaction)).getTime(), 403, 'CREDENTIAL_EXPIRED', 'This credential has expired.');
        const revoked = await transaction.query('SELECT 1 FROM credential_revocations WHERE room_id = $1 AND nullifier = $2', [row.id, verified.nullifier]);
        requireCondition(!revoked.length, 403, 'CREDENTIAL_REVOKED', 'The issuer revoked this credential for this room.');
      }
      const [existing] = await transaction.query<MemberRow>(
        `SELECT id, label, status, requested_at AS "requestedAt",
           last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at,
           credential_verified_at
         FROM memberships WHERE room_id = $1 AND session_id = $2`,
        [row.id, request.session!.id],
      );
      requireCondition(
        !existing || !['revoked', 'denied'].includes(existing.status),
        403,
        'ADMISSION_DENIED',
        'The organizer has declined access for this browser.',
      );
      const geo = geoOf(row);
      let fix: { lat: number; lng: number; accuracyM: number; distanceM: number; inside: boolean } | null = null;
      if (geo) {
        requireCondition(
          input.lat != null && input.lng != null && input.accuracyM != null && input.timestamp != null,
          403,
          'GEO_REQUIRED',
          'This room requires your location. Share your location to request access.',
        );
        const report = positionReport.parse({
          lat: input.lat,
          lng: input.lng,
          accuracyM: input.accuracyM,
          timestamp: input.timestamp,
        });
        validateFix(report);
        const distanceM = haversineMeters(report, geo);
        const inside = distanceM <= geo.radiusM;
        requireCondition(
          inside,
          403,
          'GEO_OUTSIDE',
          `You are about ${Math.round(distanceM)} m away, outside this room's area (~${geo.radiusM} m).`,
        );
        fix = { ...report, distanceM, inside };
      }
      if (existing && !fix && (!verified || existing.credential_verified_at)) return memberView(existing);
      const [member] = await transaction.query<MemberRow>(
        `INSERT INTO memberships (id, room_id, session_id, label, status, decided_at,
           credential_nullifier, credential_verified_at,
           last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at)
         VALUES ($1, $2, $3, $4, $5::varchar,
           CASE WHEN $5::varchar = 'approved' THEN clock_timestamp() ELSE NULL END,
           $6, CASE WHEN $6::text IS NULL THEN NULL ELSE clock_timestamp() END,
           $7, $8, $9, $10, $11,
           CASE WHEN $11::boolean IS NULL THEN NULL ELSE clock_timestamp() END)
         ON CONFLICT (room_id, session_id) DO UPDATE SET label = memberships.label,
           status = CASE WHEN memberships.status = 'pending' AND EXCLUDED.status = 'approved'
             THEN 'approved' ELSE memberships.status END,
           credential_nullifier = COALESCE(memberships.credential_nullifier, EXCLUDED.credential_nullifier),
           credential_verified_at = COALESCE(memberships.credential_verified_at, EXCLUDED.credential_verified_at),
           decided_at = COALESCE(memberships.decided_at, EXCLUDED.decided_at),
           last_lat = EXCLUDED.last_lat, last_lng = EXCLUDED.last_lng,
           last_accuracy_m = EXCLUDED.last_accuracy_m, last_distance_m = EXCLUDED.last_distance_m,
           last_inside = EXCLUDED.last_inside, last_checked_at = EXCLUDED.last_checked_at
         RETURNING id, label, status, requested_at AS "requestedAt",
           last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at,
           credential_verified_at`,
        [
          randomUUID(),
          row.id,
          request.session!.id,
          input.label,
          verified ? 'approved' : 'pending',
          verified?.nullifier ?? null,
          fix?.lat ?? null,
          fix?.lng ?? null,
          fix?.accuracyM ?? null,
          fix?.distanceM ?? null,
          fix?.inside ?? null,
        ],
      );
      if (!existing || (verified && !existing.credential_verified_at))
        await recordActivity(
          transaction,
          row.id,
          verified ? 'credential_proved' : 'join_requested',
          member.label,
        );
      if (verified) {
        await transaction.query('UPDATE memberships SET credential_expires_at = to_timestamp($3) WHERE room_id = $1 AND session_id = $2', [row.id, request.session!.id, verified.validUntil]);
        await transaction.query('DELETE FROM credential_challenges WHERE room_id = $1 AND session_id = $2', [row.id, request.session!.id]);
      }
      return memberView(member);
    }).catch((error: unknown) => {
      if (isCredentialReuse(error)) {
        throw new HttpError(
          409,
          'CREDENTIAL_ALREADY_USED',
          'This credential has already taken the seat it admits in this room.',
        );
      }
      throw error;
    });
    response.status(200).json(membership);
  });

  router.post('/rooms/:id/position', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const report = positionReport.parse(request.body);
    validateFix(report);
    const result = await database.transaction(async (transaction) => {
      const row = await lockRoom(transaction, id);
      const geo = geoOf(row);
      requireCondition(geo, 409, 'GEO_NOT_REQUIRED', 'This room has no location restriction.');
      requireOpen(row);
      const [membership] = await transaction.query<{ id: string }>(
        'SELECT id FROM memberships WHERE room_id = $1 AND session_id = $2',
        [id, request.session!.id],
      );
      requireCondition(membership, 403, 'ADMISSION_REQUIRED', 'Request access before sharing your location.');
      const distanceM = haversineMeters(report, geo);
      const inside = distanceM <= geo.radiusM;
      await transaction.query(
        `UPDATE memberships SET last_lat = $3, last_lng = $4, last_accuracy_m = $5,
          last_distance_m = $6, last_inside = $7, last_checked_at = clock_timestamp()
         WHERE room_id = $1 AND session_id = $2`,
        [id, request.session!.id, report.lat, report.lng, report.accuracyM, distanceM, inside],
      );
      return { inside, distanceM: Math.round(distanceM * 10) / 10, radiusM: geo.radiusM };
    });
    response.json(result);
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
      await requireParticipantAccess(database, id, request.session!.id);
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
    const rows = await database.query<MemberRow>(
      `SELECT m.id, m.label, m.status, m.requested_at AS "requestedAt",
        m.last_lat, m.last_lng, m.last_accuracy_m, m.last_distance_m, m.last_inside, m.last_checked_at,
        m.credential_verified_at
       FROM memberships m JOIN sessions s ON s.id = m.session_id
       WHERE m.room_id = $1 AND s.expires_at > clock_timestamp() ORDER BY m.requested_at`,
      [id],
    );
    response.json(rows.map(memberView));
  });

  router.patch('/rooms/:id/members/:memberId', async (request, response) => {
    const id = roomId.parse(request.params.id);
    const memberId = roomId.parse(request.params.memberId);
    const { status } = memberDecision.parse(request.body);
    const member = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.session!.id);
      requireOpen(room);
      const [current] = await transaction.query<{ status: string; credential_verified_at: Date | null }>(
        `SELECT m.status, m.credential_verified_at FROM memberships m JOIN sessions s ON s.id = m.session_id
         WHERE m.id = $1 AND m.room_id = $2 AND s.expires_at > clock_timestamp()`,
        [memberId, id],
      );
      requireCondition(current, 404, 'MEMBER_NOT_FOUND', 'Join request not found.');
      requireCondition(
        status !== 'approved' || !credentialOf(room) || current.credential_verified_at != null,
        403, 'CREDENTIAL_REQUIRED', 'This participant must prove their credential before admission.',
      );
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
