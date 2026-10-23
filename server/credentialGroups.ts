import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { joinCode, roomId } from "../shared/rooms.js";
import {
  WORKSHOP_PROOF_DEPTH,
  WORKSHOP_PROOF_VERSION,
  WORKSHOP_SCALAR_FIELD,
  workshopPolicyDigest,
} from "../shared/workshopProof.js";
import type { Database, Queries } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import { lockRoom, requireActive, requireOwner } from "./rooms.js";
import { recordActivity } from "./activity.js";

const groupInput = z
  .object({
    name: z.string().trim().min(1).max(80),
    description: z.string().trim().max(300).default(""),
  })
  .strict();
const issueInput = z
  .object({ count: z.number().int().min(1).max(20) })
  .strict();
const revokeInput = z.object({ status: z.literal("revoked") }).strict();
const enrollInput = z
  .object({
    token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    commitment: z.string().regex(/^[1-9][0-9]{0,76}$/),
  })
  .strict();
const ruleInput = z
  .object({ groupIds: z.array(z.uuid()).min(1).max(4) })
  .strict();
const tokenDigest = (token: string) =>
  createHash("sha256").update(Buffer.from(token, "base64url")).digest();
const badInvite = () => {
  throw new HttpError(
    403,
    "ENROLLMENT_INVITE_INVALID",
    "This enrollment link is invalid, unavailable, or already used. Ask the organizer for a new link.",
  );
};

interface GroupRow {
  id: string;
  owner_session_id: string;
  name: string;
  description: string;
  created_at: Date;
  owner_expires_at?: Date | null;
  owner_available?: boolean;
  owner_persistent?: boolean;
}

interface InviteRow {
  id: string;
  invite_number: number;
  created_at: Date;
  revoked_at: Date | null;
  enrolled_commitment: string | null;
}

function publicDescriptor(row: GroupRow, count: number) {
  const availableUntil = row.owner_expires_at?.toISOString() ?? null;
  const available = row.owner_available === true;
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    version: WORKSHOP_PROOF_VERSION,
    depth: WORKSHOP_PROOF_DEPTH,
    available,
    availableUntil,
    persistent: row.owner_persistent === true,
    enrolledCount: count,
  };
}

async function getRule(queries: Queries, roomIdValue: string) {
  const rows = await queries.query<{ id: string; name: string }>(
    `SELECT g.id, g.name FROM room_proof_groups rg
     JOIN credential_groups g ON g.id = rg.group_id
     JOIN owner_authorities s ON s.id = g.owner_session_id AND s.available
     WHERE rg.room_id = $1 ORDER BY g.id`,
    [roomIdValue],
  );
  const [integrity] = await queries.query<{ total: number }>(
    "SELECT count(*)::int AS total FROM room_proof_groups WHERE room_id = $1",
    [roomIdValue],
  );
  requireCondition(
    rows.length === integrity.total,
    409,
    "PROOF_RULE_UNAVAILABLE",
    "This room’s credential rule is unavailable. Contact the organizer.",
  );
  if (!rows.length) return null;
  return {
    mode: "any" as const,
    version: WORKSHOP_PROOF_VERSION,
    depth: WORKSHOP_PROOF_DEPTH,
    digest: workshopPolicyDigest(rows.map((row) => row.id)),
    groups: rows.map(({ id, name }) => ({ id, name })),
  };
}

async function lockOwnedGroups(
  transaction: Queries,
  groupIds: string[],
  ownerSessionId: string,
) {
  const ids = [...new Set(groupIds.map((id) => id.toLowerCase()))].sort();
  requireCondition(
    ids.length === groupIds.length,
    422,
    "INVALID_INPUT",
    "Choose between one and four distinct credential groups.",
  );
  const rows = await transaction.query<{ id: string }>(
    `SELECT g.id FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
     WHERE g.id = ANY($1::uuid[]) AND g.owner_session_id = $2 AND s.available
     ORDER BY g.id FOR UPDATE OF g`,
    [ids, ownerSessionId],
  );
  requireCondition(
    rows.length === ids.length,
    403,
    "CREDENTIAL_GROUP_FORBIDDEN",
    "One or more credential groups are unavailable.",
  );
  return ids;
}

export function credentialGroupRoutes(database: Database) {
  const router = Router();

  router.get("/credential-groups", async (request, response) => {
    const rows = await database.query<GroupRow & { enrolled_count: number }>(
      `SELECT g.id, g.owner_session_id, g.name, g.description, g.created_at, s.expires_at AS owner_expires_at,
         count(c.commitment)::int AS enrolled_count, s.available AS owner_available, (s.account_id IS NOT NULL) AS owner_persistent
       FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
       LEFT JOIN credential_group_commitments c ON c.group_id = g.id
       WHERE g.owner_session_id = $1 AND s.available
       GROUP BY g.id, s.expires_at, s.available, s.account_id ORDER BY g.created_at, g.id`,
      [request.ownerId],
    );
    response.json({
      groups: rows.map((row) => ({
        ...publicDescriptor(row, row.enrolled_count),
        createdAt: row.created_at.toISOString(),
      })),
    });
  });

  router.post("/credential-groups", async (request, response) => {
    const input = groupInput.parse(request.body);
    const row = await database.transaction(async (transaction) => {
      const [session] = await transaction.query<{
        expires_at: Date | null;
        available: boolean;
      }>(
        "SELECT s.expires_at, (a.id IS NOT NULL OR s.expires_at > clock_timestamp()) AS available FROM sessions s LEFT JOIN organizer_accounts a ON a.owner_session_id=s.id WHERE s.id = $1 FOR UPDATE OF s",
        [request.ownerId],
      );
      requireCondition(
        session?.available,
        401,
        "SESSION_EXPIRED",
        "Your browser session has expired. Reload the page and try again.",
      );
      const [count] = await transaction.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM credential_groups WHERE owner_session_id = $1",
        [request.ownerId],
      );
      requireCondition(
        count.total < 32,
        409,
        "CREDENTIAL_GROUP_LIMIT",
        "A browser session can create up to 32 credential groups.",
      );
      const [created] = await transaction.query<GroupRow>(
        `INSERT INTO credential_groups (id, owner_session_id, name, description) VALUES ($1, $2, $3, $4)
         RETURNING id, owner_session_id, name, description, created_at`,
        [randomUUID(), request.ownerId, input.name, input.description],
      );
      const [authority] = await transaction.query<{
        account_id: string | null;
      }>("SELECT account_id FROM owner_authorities WHERE id=$1", [
        request.ownerId,
      ]);
      return {
        ...created,
        owner_expires_at: authority?.account_id ? null : session.expires_at,
        owner_available: session.available,
        owner_persistent: !!authority?.account_id,
      };
    });
    response.status(201).json(publicDescriptor(row, 0));
  });

  router.get("/credential-groups/:id", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [group] = await database.query<GroupRow>(
      `SELECT g.id, g.owner_session_id, g.name, g.description, g.created_at, s.expires_at AS owner_expires_at,
         s.available AS owner_available, (s.account_id IS NOT NULL) AS owner_persistent
       FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
       WHERE g.id = $1 AND g.owner_session_id = $2 AND s.available`,
      [id, request.ownerId],
    );
    requireCondition(
      group,
      404,
      "CREDENTIAL_GROUP_NOT_FOUND",
      "Credential group not found.",
    );
    const rows = await database.query<InviteRow>(
      `SELECT i.id, i.invite_number, i.created_at, i.revoked_at, i.enrolled_commitment
       FROM credential_group_invites i WHERE i.group_id = $1 ORDER BY i.invite_number LIMIT 250`,
      [id],
    );
    const counts = rows.reduce(
      (value, item) => {
        if (item.revoked_at) value.revoked += 1;
        else if (item.enrolled_commitment) value.enrolled += 1;
        else value.available += 1;
        return value;
      },
      { enrolled: 0, available: 0, revoked: 0 },
    );
    response.json({
      group: {
        ...publicDescriptor(group, counts.enrolled),
        createdAt: group.created_at.toISOString(),
      },
      enrollments: rows.map((item) => ({
        id: item.id,
        number: item.invite_number,
        createdAt: item.created_at.toISOString(),
        revokedAt: item.revoked_at?.toISOString() ?? null,
        status: item.revoked_at
          ? "revoked"
          : item.enrolled_commitment
            ? "enrolled"
            : "available",
      })),
      counts,
    });
  });

  router.post(
    "/credential-groups/:id/enrollments",
    async (request, response) => {
      const id = roomId.parse(request.params.id);
      const { count } = issueInput.parse(request.body);
      const enrollments = await database.transaction(async (transaction) => {
        const [group] = await transaction.query<GroupRow>(
          `SELECT g.id, g.owner_session_id, g.name, g.description, g.created_at, s.expires_at AS owner_expires_at,
           s.available AS owner_available, (s.account_id IS NOT NULL) AS owner_persistent
         FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
         WHERE g.id = $1 FOR UPDATE OF g`,
          [id],
        );
        requireCondition(
          group &&
            group.owner_session_id === request.ownerId &&
            group.owner_available,
          404,
          "CREDENTIAL_GROUP_NOT_FOUND",
          "Credential group not found.",
        );
        const [used] = await transaction.query<{ total: number; next: number }>(
          "SELECT count(*)::int AS total, (COALESCE(max(invite_number), 0) + 1)::int AS next FROM credential_group_invites WHERE group_id = $1",
          [id],
        );
        requireCondition(
          used.total + count <= 250,
          409,
          "CREDENTIAL_GROUP_LIMIT",
          "This credential group has reached its limit of 250 lifetime enrollments.",
        );
        const result: Array<InviteRow & { token: string }> = [];
        for (let i = 0; i < count; i++) {
          const token = randomBytes(32).toString("base64url");
          const [row] = await transaction.query<InviteRow>(
            `INSERT INTO credential_group_invites (id, group_id, invite_number, token_digest) VALUES ($1, $2, $3, $4)
           RETURNING id, invite_number, created_at, revoked_at, enrolled_commitment`,
            [randomUUID(), id, used.next + i, tokenDigest(token)],
          );
          result.push({ ...row, token });
        }
        return result;
      });
      response.status(201).json({
        enrollments: enrollments.map(({ token, ...row }) => ({
          id: row.id,
          number: row.invite_number,
          token,
          createdAt: row.created_at.toISOString(),
          status: "available",
        })),
      });
    },
  );

  router.patch(
    "/credential-groups/:id/enrollments/:inviteId",
    async (request, response) => {
      const id = roomId.parse(request.params.id);
      const inviteId = roomId.parse(request.params.inviteId);
      revokeInput.parse(request.body);
      const item = await database.transaction(async (transaction) => {
        const [group] = await transaction.query<{
          id: string;
          owner_session_id: string;
          expires_at: Date;
          available: boolean;
        }>(
          `SELECT g.id, g.owner_session_id, s.expires_at,
           (s.available) AS available
         FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
         WHERE g.id = $1 FOR UPDATE OF g`,
          [id],
        );
        requireCondition(
          group &&
            group.owner_session_id === request.ownerId! &&
            group.available,
          404,
          "CREDENTIAL_GROUP_NOT_FOUND",
          "Credential group not found.",
        );
        const [current] = await transaction.query<InviteRow>(
          `SELECT id, invite_number, created_at, revoked_at, enrolled_commitment
         FROM credential_group_invites WHERE id = $1 AND group_id = $2 FOR UPDATE`,
          [inviteId, id],
        );
        requireCondition(
          current,
          404,
          "ENROLLMENT_NOT_FOUND",
          "Enrollment link not found.",
        );
        requireCondition(
          !current.enrolled_commitment,
          409,
          "ENROLLMENT_ALREADY_USED",
          "This enrollment link has already saved a credential.",
        );
        if (!current.revoked_at) {
          const [revoked] = await transaction.query<InviteRow>(
            `UPDATE credential_group_invites SET revoked_at = clock_timestamp() WHERE id = $1
           RETURNING id, invite_number, created_at, revoked_at, enrolled_commitment`,
            [inviteId],
          );
          return revoked;
        }
        return current;
      });
      response.json({
        id: item.id,
        number: item.invite_number,
        createdAt: item.created_at.toISOString(),
        revokedAt: item.revoked_at?.toISOString() ?? null,
        status: item.revoked_at ? "revoked" : "available",
      });
    },
  );

  router.get("/credentials/:id", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [group] = await database.query<GroupRow & { enrolled_count: number }>(
      `SELECT g.id, g.owner_session_id, g.name, g.description, g.created_at, s.expires_at AS owner_expires_at,
         count(c.commitment)::int AS enrolled_count, s.available AS owner_available, (s.account_id IS NOT NULL) AS owner_persistent
       FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
       LEFT JOIN credential_group_commitments c ON c.group_id = g.id
       WHERE g.id = $1 GROUP BY g.id, s.expires_at, s.available, s.account_id`,
      [id],
    );
    requireCondition(
      group,
      404,
      "CREDENTIAL_GROUP_NOT_FOUND",
      "Credential group not found.",
    );
    response.json({
      credential: publicDescriptor(group, group.enrolled_count),
    });
  });

  router.post("/credentials/:id/enroll", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const input = enrollInput.parse(request.body);
    const tokenBytes = Buffer.from(input.token, "base64url");
    if (
      tokenBytes.length !== 32 ||
      tokenBytes.toString("base64url") !== input.token ||
      BigInt(input.commitment) >= WORKSHOP_SCALAR_FIELD
    ) {
      badInvite();
    }
    const result = await database.transaction(async (transaction) => {
      const [group] = await transaction.query<{
        id: string;
        owner_session_id: string;
        expires_at: Date;
        available: boolean;
      }>(
        `SELECT g.id, g.owner_session_id, s.expires_at,
           (s.available) AS available
         FROM credential_groups g JOIN owner_authorities s ON s.id = g.owner_session_id
         WHERE g.id = $1 FOR UPDATE OF g`,
        [id],
      );
      if (!group || !group.available) {
        badInvite();
      }
      if (group.owner_session_id === request.ownerId!) {
        badInvite();
      }
      const [invite] = await transaction.query<InviteRow>(
        `SELECT id, invite_number, created_at, revoked_at, enrolled_commitment
         FROM credential_group_invites WHERE group_id = $1 AND token_digest = $2 FOR UPDATE`,
        [id, tokenDigest(input.token)],
      );
      if (!invite || invite.revoked_at) {
        badInvite();
      }
      if (invite.enrolled_commitment === input.commitment) {
        return { enrolled: true, alreadyEnrolled: true };
      }
      if (invite.enrolled_commitment) {
        badInvite();
      }
      const [exists] = await transaction.query<{ commitment: string }>(
        `SELECT commitment FROM credential_group_commitments
         WHERE group_id = $1 AND commitment = $2`,
        [id, input.commitment],
      );
      if (exists) {
        badInvite();
      }
      const [count] = await transaction.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM credential_group_invites WHERE group_id = $1",
        [id],
      );
      if (count.total > 250) {
        badInvite();
      }
      await transaction.query(
        "INSERT INTO credential_group_commitments (group_id, commitment, invite_id) VALUES ($1, $2, $3)",
        [id, input.commitment, invite.id],
      );
      await transaction.query(
        "UPDATE credential_group_invites SET enrolled_commitment = $2 WHERE id = $1",
        [invite.id, input.commitment],
      );
      return { enrolled: true, alreadyEnrolled: false };
    });
    response.json(result);
  });

  router.get("/join/:code/proof-rule", async (request, response) => {
    const code = joinCode.parse(request.params.code);
    const [room] = await database.query<{
      id: string;
      admission_policy: string;
    }>("SELECT id, admission_policy FROM rooms WHERE join_code = $1", [code]);
    requireCondition(
      room && room.admission_policy === "proof",
      404,
      "ROOM_NOT_FOUND",
      "Room not found.",
    );
    response.json({ proofRule: await getRule(database, room.id) });
  });

  router.get("/rooms/:id/proof-rule", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const [room] = await database.query<{ id: string; owner_id: string }>(
      "SELECT id, owner_id FROM rooms WHERE id = $1",
      [id],
    );
    requireCondition(room, 404, "ROOM_NOT_FOUND", "Room not found.");
    requireOwner(room, request.ownerId!);
    response.json({ proofRule: await getRule(database, id) });
  });

  router.put("/rooms/:id/proof-rule", async (request, response) => {
    const id = roomId.parse(request.params.id);
    const { groupIds } = ruleInput.parse(request.body);
    const rule = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.ownerId!);
      requireActive(room);
      requireCondition(
        room.status === "draft" && room.admission_policy === "proof",
        409,
        "PROOF_RULE_FROZEN",
        "Credential groups can be changed only while this proof room is a draft.",
      );
      const ids = await lockOwnedGroups(
        transaction,
        groupIds,
        request.ownerId!,
      );
      const [legacy] = await transaction.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM room_proof_invites WHERE room_id = $1",
        [id],
      );
      requireCondition(
        legacy.total === 0,
        409,
        "LEGACY_ENROLLMENTS_EXIST",
        "This room already has room-specific enrollment links and cannot switch to reusable groups.",
      );
      const existing = await getRule(transaction, id);
      const digest = workshopPolicyDigest(ids);
      if (existing?.digest !== digest) {
        await transaction.query(
          "DELETE FROM room_proof_groups WHERE room_id = $1",
          [id],
        );
        for (const groupId of ids) {
          await transaction.query(
            "INSERT INTO room_proof_groups (room_id, group_id) VALUES ($1, $2)",
            [id, groupId],
          );
        }
        await recordActivity(transaction, id, "proof_rule_updated");
      }
      return getRule(transaction, id);
    });
    response.json({ proofRule: rule });
  });

  router.delete("/rooms/:id/proof-rule", async (request, response) => {
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const id = roomId.parse(request.params.id);
    const rule = await database.transaction(async (transaction) => {
      const room = await lockRoom(transaction, id);
      requireOwner(room, request.ownerId!);
      requireActive(room);
      requireCondition(
        room.status === "draft",
        409,
        "PROOF_RULE_FROZEN",
        "Credential groups can be changed only while this room is a draft.",
      );
      requireCondition(
        room.admission_policy === "proof",
        409,
        "PROOF_POLICY_REQUIRED",
        "This room does not use proof admission.",
      );
      const [legacy] = await transaction.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM room_proof_invites WHERE room_id = $1",
        [id],
      );
      requireCondition(
        legacy.total === 0,
        409,
        "LEGACY_ENROLLMENTS_EXIST",
        "This room already has room-specific enrollment links and cannot switch enrollment sources.",
      );
      const [existing] = await transaction.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM room_proof_groups WHERE room_id = $1",
        [id],
      );
      if (existing.total > 0) {
        await transaction.query(
          "DELETE FROM room_proof_groups WHERE room_id = $1",
          [id],
        );
        await recordActivity(transaction, id, "proof_rule_cleared");
      }
      return null;
    });
    response.json({ proofRule: rule });
  });

  return router;
}

export async function currentProofRule(queries: Queries, roomIdValue: string) {
  return getRule(queries, roomIdValue);
}

export async function ownedProofGroupIds(
  queries: Queries,
  ids: string[],
  ownerSessionId: string,
) {
  return lockOwnedGroups(queries, ids, ownerSessionId);
}
