import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { joinCode, joinRequest, roomId } from "../shared/rooms.js";
import type { Database, Queries } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import { recordActivity } from "./activity.js";
import {
  admissionFix,
  clock,
  geoOf,
  lockRoom,
  requireActive,
  requireOpen,
  requireOwner,
} from "./rooms.js";

const issueInput = z
  .object({ count: z.number().int().min(1).max(20) })
  .strict();
const revokeInput = z.object({ status: z.literal("revoked") }).strict();
const redeemInput = joinRequest
  .extend({ token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })
  .strict();
const digest = (token: string) =>
  createHash("sha256").update(Buffer.from(token, "base64url")).digest();
const genericPassError = (): never => {
  throw new HttpError(
    403,
    "ADMISSION_PASS_INVALID",
    "This admission pass is invalid, unavailable, or already used. Ask the organizer for a new pass.",
  );
};

interface PassRow {
  id: string;
  pass_number: number;
  created_at: Date;
  revoked_at: Date | null;
  redeemed_at: Date | null;
  redeemer_session_id?: string | null;
  token_digest?: Buffer;
}

function passStatus(row: PassRow, terminal: boolean) {
  if (row.revoked_at) return "revoked";
  if (row.redeemed_at) return "used";
  return terminal ? "expired" : "available";
}

function passView(row: PassRow, terminal: boolean) {
  return {
    id: row.id,
    number: row.pass_number,
    createdAt: row.created_at.toISOString(),
    revokedAt: row.revoked_at?.toISOString() ?? null,
    redeemedAt: row.redeemed_at?.toISOString() ?? null,
    status: passStatus(row, terminal),
  };
}

async function lockRoomByCode(queries: Queries, code: string) {
  const [found] = await queries.query<{ id: string }>(
    "SELECT id FROM rooms WHERE join_code = $1",
    [code],
  );
  requireCondition(found, 404, "ROOM_NOT_FOUND", "Room not found.");
  return lockRoom(queries, found.id);
}

export function passRoutes(database: Database) {
  const router = Router();

  router.get("/rooms/:id/passes", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [room] = await database.query<{
      id: string;
      owner_id: string;
      status: string;
      expires_at: Date;
      admission_policy: string;
    }>(
      "SELECT id, owner_id, status, expires_at, admission_policy FROM rooms WHERE id = $1",
      [id],
    );
    requireCondition(room, 404, "ROOM_NOT_FOUND", "Room not found.");
    requireOwner(room, request.ownerId!);
    requireCondition(
      room.admission_policy === "pass",
      409,
      "PASS_POLICY_REQUIRED",
      "This room does not use admission passes.",
    );
    const terminal =
      room.status === "closed" || room.expires_at <= (await clock(database));
    const rows = await database.query<PassRow>(
      `SELECT id, pass_number, created_at, revoked_at, redeemed_at
       FROM room_admission_passes WHERE room_id = $1 ORDER BY pass_number LIMIT 1000`,
      [id],
    );
    response.json(rows.map((row) => passView(row, terminal)));
  });

  router.post("/rooms/:id/passes", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { count } = issueInput.parse(request.body);
    const result = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.ownerId!);
      requireActive(room);
      requireCondition(
        room.admission_policy === "pass",
        409,
        "PASS_POLICY_REQUIRED",
        "This room does not use admission passes.",
      );
      const [used] = await transaction.query<{ total: number; next: number }>(
        `SELECT count(*)::int AS total, (COALESCE(max(pass_number), 0) + 1)::int AS next
         FROM room_admission_passes WHERE room_id = $1`,
        [id],
      );
      requireCondition(
        used.total + count <= 1000,
        409,
        "PASS_LIMIT",
        "This room has reached its limit of 1,000 passes.",
      );
      const passes: Array<ReturnType<typeof passView> & { token: string }> = [];
      for (let offset = 0; offset < count; offset += 1) {
        const token = randomBytes(32).toString("base64url");
        const [row] = await transaction.query<PassRow>(
          `INSERT INTO room_admission_passes (id, room_id, pass_number, token_digest)
           VALUES ($1, $2, $3, $4) RETURNING id, pass_number, created_at, revoked_at, redeemed_at`,
          [randomUUID(), id, used.next + offset, digest(token)],
        );
        passes.push({ ...passView(row, false), token });
      }
      await recordActivity(transaction, id, "admission_passes_issued");
      return passes;
    });
    response.status(201).json({ passes: result });
  });

  router.patch("/rooms/:id/passes/:passId", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const passId = roomId.parse(request.params.passId);
    revokeInput.parse(request.body);
    const pass = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.ownerId!);
      requireActive(room);
      requireCondition(
        room.admission_policy === "pass",
        409,
        "PASS_POLICY_REQUIRED",
        "This room does not use admission passes.",
      );
      const [current] = await transaction.query<PassRow>(
        `SELECT id, pass_number, created_at, revoked_at, redeemed_at FROM room_admission_passes
         WHERE id = $1 AND room_id = $2 FOR UPDATE`,
        [passId, id],
      );
      requireCondition(
        current,
        404,
        "PASS_NOT_FOUND",
        "Admission pass not found.",
      );
      requireCondition(
        !current.redeemed_at,
        409,
        "PASS_ALREADY_USED",
        "This pass has already been used. Remove participant access from the participant list instead.",
      );
      if (!current.revoked_at) {
        const [updated] = await transaction.query<PassRow>(
          `UPDATE room_admission_passes SET revoked_at = clock_timestamp() WHERE id = $1
           RETURNING id, pass_number, created_at, revoked_at, redeemed_at`,
          [passId],
        );
        await recordActivity(transaction, id, "pass_revoked");
        return updated;
      }
      return current;
    });
    response.json(passView(pass, false));
  });

  router.post("/join/:code/redeem", async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const input = redeemInput.parse(request.body);
    const canonical = Buffer.from(input.token, "base64url").toString(
      "base64url",
    );
    if (
      canonical !== input.token ||
      Buffer.from(input.token, "base64url").length !== 32
    )
      genericPassError();
    const member = await database.transaction(async (transaction) => {
      const room = await lockRoomByCode(transaction, code);
      requireOpen(room);
      requireCondition(
        room.admission_policy === "pass",
        409,
        "PASS_POLICY_REQUIRED",
        "This room does not accept admission passes.",
      );
      requireCondition(
        room.owner_id !== request.ownerId &&
          room.owner_id !== request.session!.id,
        409,
        "ALREADY_OWNER",
        "You already organize this room.",
      );
      const [pass] = await transaction.query<PassRow>(
        `SELECT id, pass_number, created_at, revoked_at, redeemed_at, redeemer_session_id
         FROM room_admission_passes WHERE room_id = $1 AND token_digest = $2 FOR UPDATE`,
        [room.id, digest(input.token)],
      );
      if (!pass || pass.revoked_at) genericPassError();

      const [existing] = await transaction.query<{
        id: string;
        label: string;
        status: string;
      }>(
        "SELECT id, label, status FROM memberships WHERE room_id = $1 AND session_id = $2 FOR UPDATE",
        [room.id, request.session!.id],
      );
      requireCondition(
        !existing || !["revoked", "denied"].includes(existing.status),
        403,
        "ADMISSION_DENIED",
        "The organizer has declined access for this browser.",
      );

      if (pass.redeemed_at) {
        const sameBrowser = pass.redeemer_session_id === request.session!.id;
        if (!sameBrowser || existing?.status !== "approved") genericPassError();
        admissionFix(input, geoOf(room));
        return {
          id: existing.id,
          label: existing.label,
          status: existing.status,
        };
      }
      requireCondition(
        existing?.status !== "approved",
        409,
        "ALREADY_ADMITTED",
        "This browser already has access. The unused pass was not consumed.",
      );
      const fix = admissionFix(input, geoOf(room));

      const [updated] = await transaction.query<{
        id: string;
        label: string;
        status: string;
      }>(
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
        [
          randomUUID(),
          room.id,
          request.session!.id,
          input.label,
          fix?.lat ?? null,
          fix?.lng ?? null,
          fix?.accuracyM ?? null,
          fix?.distanceM ?? null,
          fix?.inside ?? null,
        ],
      );
      await transaction.query(
        `UPDATE room_admission_passes
         SET redeemed_at = clock_timestamp(), redeemer_session_id = $2
         WHERE id = $1`,
        [pass.id, request.session!.id],
      );
      await recordActivity(
        transaction,
        room.id,
        "pass_redeemed",
        updated.label,
      );
      return updated;
    });
    response.json(member);
  });

  return router;
}
