import { randomBytes, randomUUID } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import {
  geoAreaInput,
  joinCode,
  joinRequest,
  memberDecision,
  placeQuery,
  positionReport,
  roomId,
  roomInput,
  roomTemplateInput,
  type GeoRule,
  type Room,
  type RoomInput,
  type PublicRoom,
} from "../shared/rooms.js";
import { haversineMeters } from "../shared/geo.js";
import type { Database, Queries } from "./database.js";
import { requireCondition } from "./errors.js";
import type { Geocoder } from "./geocoding.js";
import { activityQuery, readActivity, recordActivity } from "./activity.js";
import type { ActivityKind, RoomField } from "../shared/activity.js";

interface RoomRow {
  id: string;
  owner_id: string;
  join_code: string;
  title: string;
  description: string;
  status: "draft" | "open" | "closed";
  expires_at: Date;
  created_at: Date;
  geo_lat: number | null;
  geo_lng: number | null;
  geo_radius_m: number | null;
  geo_label: string | null;
  is_expired: boolean;
  membership_status: Room["membershipStatus"];
  submission_cleanup_enabled: boolean;
  submissions_purged_at: Date | null;
  admission_policy: "approval" | "pass" | "proof";
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
}

const selection = `SELECT r.*, r.expires_at <= clock_timestamp() AS is_expired,
  m.status AS membership_status FROM rooms r
  LEFT JOIN memberships m ON m.room_id = r.id AND m.session_id = $1`;

export function geoOf(row: RoomRow): GeoRule | null {
  if (row.geo_lat == null || row.geo_lng == null || row.geo_radius_m == null)
    return null;
  return { lat: row.geo_lat, lng: row.geo_lng, radiusM: row.geo_radius_m };
}

function roomView(row: RoomRow, sessionId: string): Room {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status:
      row.status === "closed"
        ? "closed"
        : row.is_expired
          ? "expired"
          : row.status,
    expiresAt: row.expires_at.toISOString(),
    createdAt: row.created_at.toISOString(),
    joinCode: row.join_code,
    submissionCleanupEnabled: row.submission_cleanup_enabled,
    submissionsPurgedAt: row.submissions_purged_at?.toISOString() ?? null,
    role: row.owner_id === sessionId ? "owner" : "participant",
    membershipStatus: row.membership_status ?? null,
    geo: geoOf(row),
    geoLabel: row.geo_label,
    admissionPolicy: row.admission_policy ?? "approval",
  };
}

function publicView(
  row: RoomRow,
  ownerId: string | null,
  key: { fingerprint: string; publicKey: string } | null,
): PublicRoom {
  const view = roomView(row, ownerId ?? "");
  return {
    id: view.id,
    title: view.title,
    description: view.description,
    status: view.status,
    expiresAt: view.expiresAt,
    membershipStatus: view.membershipStatus,
    isOwner: view.role === "owner",
    organizerKeyFingerprint: key?.fingerprint ?? null,
    organizerPublicKey: key?.publicKey ?? null,
    submissionCleanupEnabled: view.submissionCleanupEnabled,
    submissionsPurgedAt: view.submissionsPurgedAt,
    geo: view.geo,
    geoLabel: view.geoLabel,
    needsLocation:
      view.geo != null &&
      view.role !== "owner" &&
      view.membershipStatus !== "approved",
    admissionPolicy: view.admissionPolicy,
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
      row.last_distance_m == null
        ? null
        : Math.round((row.last_distance_m as number) * 10) / 10,
    accuracyM:
      row.last_accuracy_m == null
        ? null
        : Math.round((row.last_accuracy_m as number) * 10) / 10,
    checkedAt: row.last_checked_at
      ? (row.last_checked_at as Date).toISOString()
      : null,
  };
}

const ENTRY_FRESH_MS = 5 * 60 * 1000;
const FIX_FRESH_MS = 60 * 1000;
const ACCURACY_CAP_M = 75;

export function validateFix(input: {
  lat: number;
  lng: number;
  accuracyM: number;
  timestamp: string;
}) {
  requireCondition(
    input.accuracyM <= ACCURACY_CAP_M,
    422,
    "GEO_INACCURATE",
    `Location accuracy is too low (${Math.round(input.accuracyM)} m). Move near a window or outdoors and try again.`,
  );
  const age = Date.now() - new Date(input.timestamp).getTime();
  requireCondition(
    Number.isFinite(age) && age >= -30 * 1000 && age <= FIX_FRESH_MS,
    422,
    "GEO_STALE",
    "Location reading is stale. Share a fresh location.",
  );
}

export async function clock(queries: Queries) {
  const [row] = await queries.query<{ now: Date }>(
    "SELECT clock_timestamp() AS now",
  );
  return row.now;
}

export async function lockRoom(queries: Queries, id: string) {
  const [row] = await queries.query<RoomRow>(
    "SELECT * FROM rooms WHERE id = $1 FOR UPDATE",
    [id],
  );
  requireCondition(row, 404, "ROOM_NOT_FOUND", "Room not found.");
  row.is_expired = row.expires_at <= (await clock(queries));
  return row;
}

export function requireOwner(row: { owner_id: string }, sessionId: string) {
  requireCondition(
    row.owner_id === sessionId,
    403,
    "OWNER_REQUIRED",
    "Only the organizer can do this.",
  );
}

function requireOwnerId(request: { ownerId: string | null }) {
  requireCondition(
    request.ownerId,
    401,
    "ORGANIZER_REQUIRED",
    "Sign in to an organizer account to manage this workspace.",
  );
  return request.ownerId;
}

export function requireActive(row: { status: string; is_expired: boolean }) {
  requireCondition(
    row.status !== "closed" && !row.is_expired,
    410,
    "ROOM_CLOSED",
    "This room has closed.",
  );
}

export function requireOpen(row: { status: string; is_expired: boolean }) {
  requireActive(row);
  requireCondition(
    row.status === "open",
    409,
    "ROOM_NOT_OPEN",
    "This room is not open yet.",
  );
}

export function admissionFix(
  input: { lat?: number; lng?: number; accuracyM?: number; timestamp?: string },
  geo: GeoRule | null,
) {
  if (!geo) return null;
  requireCondition(
    input.lat != null &&
      input.lng != null &&
      input.accuracyM != null &&
      input.timestamp != null,
    403,
    "GEO_REQUIRED",
    "This room requires your location. Share your location to request access.",
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
    "GEO_OUTSIDE",
    `You are about ${Math.round(distanceM)} m away, outside this room's area (~${geo.radiusM} m).`,
  );
  return { ...report, distanceM, inside };
}

function validateExpiry(value: string, now: Date, ownerExpiry: Date | null) {
  const expiresAt = new Date(value);
  requireCondition(
    expiresAt > now,
    422,
    "INVALID_EXPIRY",
    "Choose an expiry time in the future.",
  );
  requireCondition(
    expiresAt.getTime() - now.getTime() <= 7 * 24 * 60 * 60 * 1000,
    422,
    "INVALID_EXPIRY",
    "A room can remain available for up to seven days.",
  );
  if (ownerExpiry)
    requireCondition(
      expiresAt < ownerExpiry,
      422,
      "SESSION_TOO_SHORT",
      "Room expiry must be before your browser session expires.",
    );
  return expiresAt;
}

async function insertRoom(
  queries: Queries,
  ownerId: string,
  input: RoomInput,
  kind: Extract<
    ActivityKind,
    "room_created" | "room_duplicated"
  > = "room_created",
) {
  const [authority] = await queries.query<{
    available: boolean;
    expires_at: Date | null;
  }>("SELECT available,expires_at FROM owner_authorities WHERE id=$1", [
    ownerId,
  ]);
  requireCondition(
    authority?.available,
    401,
    "ORGANIZER_REQUIRED",
    "Sign in to an organizer account to manage this workspace.",
  );
  const expiresAt = validateExpiry(
    input.expiresAt,
    await clock(queries),
    authority.expires_at,
  );
  const [row] = await queries.query<RoomRow>(
    `INSERT INTO rooms (id, owner_id, join_code, title, description, expires_at, admission_policy)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *, false AS is_expired`,
    [
      randomUUID(),
      ownerId,
      randomBytes(12).toString("base64url"),
      input.title,
      input.description,
      expiresAt,
      input.admissionPolicy ?? "approval",
    ],
  );
  await recordActivity(queries, row.id, kind);
  return roomView(row, ownerId);
}

export function roomRoutes(database: Database, geocoder: Geocoder) {
  const router = Router();

  router.get("/rooms", async (request, response) => {
    const sessionId = request.session!.id;
    const ownerId = request.ownerId;
    const rows = await database.query<RoomRow>(
      `${selection}
      WHERE ($2::uuid IS NOT NULL AND r.owner_id = $2) OR m.session_id = $1 ORDER BY r.created_at DESC`,
      [sessionId, ownerId],
    );
    response.json(rows.map((row) => roomView(row, ownerId ?? "")));
  });

  router.post("/rooms", async (request, response) => {
    const input = roomInput.parse(request.body);
    response
      .status(201)
      .json(
        await database.transaction((transaction) =>
          insertRoom(transaction, requireOwnerId(request), input),
        ),
      );
  });

  router.post("/rooms/:id/duplicate", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = roomTemplateInput.parse(request.body);
    const room = await database.transaction(async (transaction) => {
      const original = await lockRoom(transaction, id);
      requireOwner(original, requireOwnerId(request));
      const duplicate = await insertRoom(
        transaction,
        requireOwnerId(request),
        {
          title: input.title ?? original.title,
          description: input.description ?? original.description,
          expiresAt: input.expiresAt,
          admissionPolicy: input.admissionPolicy ?? original.admission_policy,
        },
        "room_duplicated",
      );
      const resultantPolicy =
        input.admissionPolicy ?? original.admission_policy;
      if (
        resultantPolicy === "proof" &&
        original.admission_policy === "proof"
      ) {
        const [bound] = await transaction.query<{ total: number }>(
          "SELECT count(*)::int AS total FROM room_proof_groups WHERE room_id = $1",
          [original.id],
        );
        const copied = await transaction.query<{ group_id: string }>(
          `INSERT INTO room_proof_groups (room_id, group_id)
           SELECT $1, rg.group_id FROM room_proof_groups rg
           JOIN credential_groups g ON g.id = rg.group_id AND g.owner_session_id = $3
           JOIN owner_authorities s ON s.id = g.owner_session_id AND s.available
           WHERE rg.room_id = $2 RETURNING group_id`,
          [duplicate.id, original.id, requireOwnerId(request)],
        );
        requireCondition(
          copied.length === bound.total,
          409,
          "PROOF_RULE_UNAVAILABLE",
          "The template’s credential rule is unavailable and could not be copied.",
        );
      }
      return duplicate;
    });
    response.status(201).json(room);
  });

  router.get("/join/:code", async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const [row] = await database.query<RoomRow>(
      `${selection} WHERE r.join_code = $2`,
      [request.session!.id, code],
    );
    requireCondition(row, 404, "ROOM_NOT_FOUND", "Room not found.");
    const [recipientKey] = await database.query<{
      publicKey: Buffer;
      fingerprint: string;
    }>(
      'SELECT public_key AS "publicKey", fingerprint FROM room_recipient_keys WHERE room_id = $1',
      [row.id],
    );
    response.json(
      publicView(
        row,
        request.ownerId,
        recipientKey
          ? {
              fingerprint: recipientKey.fingerprint,
              publicKey: Buffer.from(recipientKey.publicKey).toString("base64"),
            }
          : null,
      ),
    );
  });

  router.get("/geo/search", async (request, response) => {
    const { q } = placeQuery.parse(request.query);
    response.json({ results: await geocoder.search(q) });
  });

  router.post("/rooms/:id/geo", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = geoAreaInput.parse(request.body);
    const [existing] = await database.query<RoomRow>(
      "SELECT * FROM rooms WHERE id = $1",
      [id],
    );
    requireCondition(existing, 404, "ROOM_NOT_FOUND", "Room not found.");
    requireOwner(existing, requireOwnerId(request));
    const label = input.label ?? (await geocoder.reverse(input.lat, input.lng));
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, requireOwnerId(request));
      requireActive(room);
      requireCondition(
        room.status === "draft",
        409,
        "INVALID_TRANSITION",
        "Only a draft room can be restricted to an area.",
      );
      const [updated] = await transaction.query<RoomRow>(
        `UPDATE rooms SET geo_lat = $2, geo_lng = $3, geo_radius_m = $4, geo_label = $5,
           geo_source = $6
         WHERE id = $1 RETURNING *, false AS is_expired`,
        [id, input.lat, input.lng, input.radiusM, label, input.source ?? null],
      );
      return updated;
    });
    response.json(roomView(row, request.ownerId ?? ""));
  });

  router.delete("/rooms/:id/geo", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, requireOwnerId(request));
      requireActive(room);
      requireCondition(
        room.status === "draft",
        409,
        "INVALID_TRANSITION",
        "Only a draft room can change its area.",
      );
      const [updated] = await transaction.query<RoomRow>(
        `UPDATE rooms SET geo_lat = NULL, geo_lng = NULL, geo_radius_m = NULL,
           geo_label = NULL, geo_source = NULL
         WHERE id = $1 RETURNING *, false AS is_expired`,
        [id],
      );
      return updated;
    });
    response.json(roomView(row, request.ownerId ?? ""));
  });

  router.post("/join/:code", async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const input = joinRequest.parse(request.body);
    const membership = await database.transaction(async (transaction) => {
      const [found] = await transaction.query<RoomRow>(
        "SELECT * FROM rooms WHERE join_code = $1",
        [code],
      );
      requireCondition(found, 404, "ROOM_NOT_FOUND", "Room not found.");
      const row = await lockRoom(transaction, found.id);
      requireOpen(row);
      requireCondition(
        row.admission_policy === "approval",
        409,
        row.admission_policy === "proof" ? "PROOF_REQUIRED" : "PASS_REQUIRED",
        row.admission_policy === "proof"
          ? "This room requires a saved workshop credential and a valid membership proof."
          : "This room requires an admission pass from the organizer.",
      );
      requireCondition(
        row.owner_id !== request.ownerId &&
          row.owner_id !== request.session!.id,
        409,
        "ALREADY_OWNER",
        "You already organize this room.",
      );
      const [existing] = await transaction.query<MemberRow>(
        `SELECT id, label, status, requested_at AS "requestedAt",
           last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at
         FROM memberships WHERE room_id = $1 AND session_id = $2`,
        [row.id, request.session!.id],
      );
      requireCondition(
        !existing || !["revoked", "denied"].includes(existing.status),
        403,
        "ADMISSION_DENIED",
        "The organizer has declined access for this browser.",
      );
      const fix = admissionFix(input, geoOf(row));
      if (existing && !fix) return memberView(existing);
      const [member] = await transaction.query<MemberRow>(
        `INSERT INTO memberships (id, room_id, session_id, label, last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CASE WHEN $9::boolean IS NULL THEN NULL ELSE clock_timestamp() END)
         ON CONFLICT (room_id, session_id) DO UPDATE SET label = memberships.label,
           last_lat = EXCLUDED.last_lat, last_lng = EXCLUDED.last_lng,
           last_accuracy_m = EXCLUDED.last_accuracy_m, last_distance_m = EXCLUDED.last_distance_m,
           last_inside = EXCLUDED.last_inside, last_checked_at = EXCLUDED.last_checked_at
         RETURNING id, label, status, requested_at AS "requestedAt",
           last_lat, last_lng, last_accuracy_m, last_distance_m, last_inside, last_checked_at`,
        [
          randomUUID(),
          row.id,
          request.session!.id,
          input.label,
          fix?.lat ?? null,
          fix?.lng ?? null,
          fix?.accuracyM ?? null,
          fix?.distanceM ?? null,
          fix?.inside ?? null,
        ],
      );
      if (!existing)
        await recordActivity(
          transaction,
          row.id,
          "join_requested",
          member.label,
        );
      return memberView(member);
    });
    response.status(200).json(membership);
  });

  router.post("/rooms/:id/position", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const report = positionReport.parse(request.body);
    validateFix(report);
    const result = await database.transaction(async (transaction) => {
      const row = await lockRoom(transaction, id);
      const geo = geoOf(row);
      requireCondition(
        geo,
        409,
        "GEO_NOT_REQUIRED",
        "This room has no location restriction.",
      );
      requireOpen(row);
      const [membership] = await transaction.query<{ id: string }>(
        "SELECT id FROM memberships WHERE room_id = $1 AND session_id = $2",
        [id, request.session!.id],
      );
      requireCondition(
        membership,
        403,
        "ADMISSION_REQUIRED",
        "Request access before sharing your location.",
      );
      const distanceM = haversineMeters(report, geo);
      const inside = distanceM <= geo.radiusM;
      await transaction.query(
        `UPDATE memberships SET last_lat = $3, last_lng = $4, last_accuracy_m = $5,
          last_distance_m = $6, last_inside = $7, last_checked_at = clock_timestamp()
         WHERE room_id = $1 AND session_id = $2`,
        [
          id,
          request.session!.id,
          report.lat,
          report.lng,
          report.accuracyM,
          distanceM,
          inside,
        ],
      );
      return {
        inside,
        distanceM: Math.round(distanceM * 10) / 10,
        radiusM: geo.radiusM,
      };
    });
    response.json(result);
  });

  router.get("/rooms/:id", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [row] = await database.query<RoomRow>(
      `${selection} WHERE r.id = $2`,
      [request.session!.id, id],
    );
    requireCondition(row, 404, "ROOM_NOT_FOUND", "Room not found.");
    if (row.owner_id !== request.ownerId) {
      requireCondition(
        row.membership_status === "approved",
        403,
        "ADMISSION_REQUIRED",
        "Organizer approval is required.",
      );
      requireOpen(row);
      const geo = geoOf(row);
      if (geo) {
        const [membership] = await database.query<{
          last_inside: boolean | null;
          last_checked_at: Date | null;
        }>(
          "SELECT last_inside, last_checked_at FROM memberships WHERE room_id = $1 AND session_id = $2",
          [id, request.session!.id],
        );
        requireCondition(
          membership?.last_checked_at,
          403,
          "GEO_STALE",
          "Share a fresh location to enter this room.",
        );
        const age =
          Date.now() - new Date(membership.last_checked_at as Date).getTime();
        requireCondition(
          age <= ENTRY_FRESH_MS,
          403,
          "GEO_STALE",
          "Share a fresh location to enter this room.",
        );
        requireCondition(
          membership.last_inside === true,
          403,
          "GEO_OUTSIDE",
          "You are outside this room\u2019s area.",
        );
      }
    }
    response.json(roomView(row, request.ownerId ?? ""));
  });

  router.patch("/rooms/:id", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = roomInput.parse(request.body);
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, requireOwnerId(request));
      requireActive(room);
      const [authority] = await transaction.query<{
        available: boolean;
        expires_at: Date | null;
      }>("SELECT available,expires_at FROM owner_authorities WHERE id=$1", [
        requireOwnerId(request),
      ]);
      requireCondition(
        authority?.available,
        401,
        "ORGANIZER_REQUIRED",
        "Sign in to an organizer account to manage this workspace.",
      );
      const expiresAt = validateExpiry(
        input.expiresAt,
        await clock(transaction),
        authority.expires_at,
      );
      const [updated] = await transaction.query<RoomRow>(
        `UPDATE rooms SET title = $2, description = $3, expires_at = $4, admission_policy = $5
         WHERE id = $1 RETURNING *, false AS is_expired`,
        [
          id,
          input.title,
          input.description,
          expiresAt,
          input.admissionPolicy ?? room.admission_policy,
        ],
      );
      if (
        input.admissionPolicy &&
        input.admissionPolicy !== "proof" &&
        room.admission_policy === "proof"
      ) {
        await transaction.query(
          "DELETE FROM room_proof_groups WHERE room_id = $1",
          [id],
        );
      }
      const changedFields: RoomField[] = [];
      if (room.title !== input.title) changedFields.push("title");
      if (room.description !== input.description)
        changedFields.push("description");
      if (room.expires_at.getTime() !== expiresAt.getTime())
        changedFields.push("expiresAt");
      if (
        input.admissionPolicy &&
        room.admission_policy !== input.admissionPolicy
      ) {
        requireCondition(
          room.status === "draft",
          409,
          "POLICY_LOCKED",
          "Admission policy can only change while the room is a draft.",
        );
        changedFields.push("admissionPolicy");
      }
      if (changedFields.length)
        await recordActivity(
          transaction,
          id,
          "room_updated",
          null,
          changedFields,
        );
      return updated;
    });
    response.json(roomView(row, request.ownerId ?? ""));
  });

  router.post("/rooms/:id/submission-cleanup", async (request, response) => {
    const id = roomId.parse(request.params.id);
    z.object({}).strict().parse(request.body);
    const row = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, requireOwnerId(request));
      if (!room.submission_cleanup_enabled) {
        const [updated] = await transaction.query<RoomRow>(
          "UPDATE rooms SET submission_cleanup_enabled = TRUE WHERE id = $1 RETURNING *, expires_at <= clock_timestamp() AS is_expired",
          [id],
        );
        await recordActivity(transaction, id, "submission_cleanup_enabled");
        return updated;
      }
      return room;
    });
    response.json(roomView(row, request.ownerId ?? ""));
  });

  for (const action of ["open", "close"] as const) {
    router.post(`/rooms/:id/${action}`, async (request, response) => {
      const id = roomId.parse(request.params.id);
      const row = await database.transaction(async (transaction) => {
        const room = await lockRoom(transaction, id);
        requireOwner(room, requireOwnerId(request));
        requireActive(room);
        if (action === "open")
          requireCondition(
            room.status === "draft",
            409,
            "INVALID_TRANSITION",
            "Only a draft room can be opened.",
          );
        const [updated] = await transaction.query<RoomRow>(
          `UPDATE rooms SET status = $2::varchar, closed_at = CASE WHEN $2::varchar = 'closed' THEN clock_timestamp() ELSE NULL END
           WHERE id = $1 RETURNING *, false AS is_expired`,
          [id, action === "open" ? "open" : "closed"],
        );
        await recordActivity(
          transaction,
          id,
          action === "open" ? "room_opened" : "room_closed",
        );
        return updated;
      });
      response.json(roomView(row, request.ownerId ?? ""));
    });
  }

  router.get("/rooms/:id/activity", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { before } = activityQuery.parse(request.query);
    const [room] = await database.query<RoomRow>(
      "SELECT * FROM rooms WHERE id = $1",
      [id],
    );
    requireCondition(room, 404, "ROOM_NOT_FOUND", "Room not found.");
    requireOwner(room, requireOwnerId(request));
    response.json(await readActivity(database, id, before));
  });

  router.get("/rooms/:id/members", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [room] = await database.query<RoomRow>(
      "SELECT * FROM rooms WHERE id = $1",
      [id],
    );
    requireCondition(room, 404, "ROOM_NOT_FOUND", "Room not found.");
    requireOwner(room, requireOwnerId(request));
    const rows = await database.query<MemberRow>(
      `SELECT m.id, m.label, m.status, m.requested_at AS "requestedAt",
        m.last_lat, m.last_lng, m.last_accuracy_m, m.last_distance_m, m.last_inside, m.last_checked_at
       FROM memberships m JOIN sessions s ON s.id = m.session_id
       WHERE m.room_id = $1 AND s.expires_at > clock_timestamp() ORDER BY m.requested_at`,
      [id],
    );
    response.json(rows.map(memberView));
  });

  router.patch("/rooms/:id/members/:memberId", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const memberId = roomId.parse(request.params.memberId);
    const { status } = memberDecision.parse(request.body);
    const member = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, requireOwnerId(request));
      requireOpen(room);
      const [current] = await transaction.query<{ status: string }>(
        `SELECT m.status FROM memberships m JOIN sessions s ON s.id = m.session_id
         WHERE m.id = $1 AND m.room_id = $2 AND s.expires_at > clock_timestamp()`,
        [memberId, id],
      );
      requireCondition(
        current,
        404,
        "MEMBER_NOT_FOUND",
        "Join request not found.",
      );
      const allowed =
        status === "revoked"
          ? current.status === "approved"
          : current.status === "pending";
      requireCondition(
        allowed,
        409,
        "INVALID_TRANSITION",
        "This membership cannot make that transition.",
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
