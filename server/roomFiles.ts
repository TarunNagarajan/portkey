import { createHash } from "node:crypto";
import express from "express";
import { Router } from "express";
import { z } from "zod";
import type { Database, Queries } from "./database.js";
import { requireCondition } from "./errors.js";
import { roomId } from "../shared/rooms.js";
import { requireRoomLocation } from "./roomAccess.js";
const MiB = 1024 * 1024,
  MAX = 250 * MiB,
  CHUNK = MiB,
  QUOTA = 5 * 1024 * 1024 * 1024;
const b64 = z
  .string()
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const canonicalB64 = (value: string) =>
  Buffer.from(value, "base64").toString("base64") === value;
const hash = (b: Buffer) => createHash("sha256").update(b).digest("hex");
type Policy = {
  id: string;
  owner_id: string;
  status: string;
  expired: boolean;
};
type FileReceipt = {
  id: string;
  acceptedAt: Date | string;
  encryptedBytes: number;
  manifestSha256: string;
};
async function getRoom(q: Queries, id: string): Promise<Policy> {
  const [r] = await q.query<Policy>(
    `SELECT id,owner_id,status,expires_at <= clock_timestamp() AS expired FROM rooms WHERE id=$1`,
    [id],
  );
  requireCondition(r, 404, "ROOM_NOT_FOUND", "Room not found.");
  return r;
}
async function admit(
  q: Queries,
  r: Policy,
  ownerId: string | null,
  sessionId: string,
) {
  const [fresh] = await q.query<{
    status: string;
    expired: boolean;
  }>(
    "SELECT status,expires_at <= clock_timestamp() AS expired FROM rooms WHERE id=$1",
    [r.id],
  );
  requireCondition(
    fresh.status === "open" && !fresh.expired,
    410,
    "ROOM_CLOSED",
    "This room is no longer accepting shared files.",
  );
  if (r.owner_id === ownerId) return { uploader: r.owner_id, owner: true };
  const [m] = await q.query<{
    status: string;
  }>(
    "SELECT m.status FROM memberships m JOIN sessions s ON s.id=m.session_id WHERE m.room_id=$1 AND m.session_id=$2 AND s.expires_at>clock_timestamp()",
    [r.id, sessionId],
  );
  requireCondition(
    m?.status === "approved",
    403,
    "ADMISSION_REQUIRED",
    "Organizer approval is required.",
  );
  await requireRoomLocation(q, r.id, sessionId);
  return { uploader: sessionId, owner: false };
}
async function locked(q: Queries, id: string) {
  const [r] = await q.query<Policy>(
    "SELECT id,owner_id,status,expires_at <= clock_timestamp() AS expired FROM rooms WHERE id=$1 FOR UPDATE",
    [id],
  );
  requireCondition(r, 404, "ROOM_NOT_FOUND", "Room not found.");
  return r;
}
const fileShape = z
  .object({
    id: roomId,
    keyFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
    descriptor: b64,
    chunkCount: z.number().int().min(1).max(250),
    encryptedBytes: z
      .number()
      .int()
      .min(16)
      .max(MAX + 4000),
  })
  .strict();
export function roomFilesRoutes(db: Database) {
  const router = Router();
  router.use("/rooms/:roomId/files/:fileId/chunks/:index", (req, res, next) => {
    if (req.method !== "PUT") return next();
    void (async () => {
      const rid = roomId.parse(req.params.roomId),
        fid = roomId.parse(req.params.fileId),
        r = await getRoom(db, rid);
      const who = await admit(db, r, req.ownerId, req.session!.id);
      const [f] = await db.query<{
        uploader_id: string;
        status: string;
      }>(
        "SELECT uploader_id,status FROM room_files WHERE id=$1 AND room_id=$2",
        [fid, rid],
      );
      requireCondition(
        f && f.uploader_id === who.uploader,
        404,
        "FILE_NOT_FOUND",
        "File not found.",
      );
      requireCondition(
        f.status === "uploading",
        409,
        "UPLOAD_COMPLETE",
        "File upload is complete.",
      );
      express.raw({ type: "application/octet-stream", limit: CHUNK + 16 })(
        req,
        res,
        next,
      );
    })().catch(next);
  });
  router.get("/rooms/:id/files/key", async (req, res) => {
    const id = roomId.parse(req.params.id),
      r = await getRoom(db, id);
    if (r.owner_id !== req.ownerId)
      await admit(db, r, req.ownerId, req.session!.id);
    else
      requireCondition(
        !r.expired && r.status !== "closed",
        410,
        "ROOM_CLOSED",
        "This room has closed.",
      );
    const [k] = await db.query<{
      fingerprint: string;
    }>("SELECT fingerprint FROM room_file_keys WHERE room_id=$1", [id]);
    res.json({ fingerprint: k?.fingerprint ?? null });
  });
  router.post("/rooms/:id/files/key", async (req, res) => {
    const id = roomId.parse(req.params.id),
      { fingerprint } = z
        .object({ fingerprint: z.string().regex(/^[0-9a-f]{64}$/) })
        .strict()
        .parse(req.body);
    await db.transaction(async (tx) => {
      const r = await locked(tx, id);
      requireCondition(
        r.owner_id === req.ownerId,
        403,
        "OWNER_REQUIRED",
        "Only the organizer can register the room key.",
      );
      const [fresh] = await tx.query<{ status: string; expired: boolean }>(
        "SELECT status,expires_at <= clock_timestamp() AS expired FROM rooms WHERE id=$1",
        [id],
      );
      requireCondition(
        fresh.status !== "closed" && !fresh.expired,
        410,
        "ROOM_CLOSED",
        "This room has closed.",
      );
      const [old] = await tx.query<{
        fingerprint: string;
      }>("SELECT fingerprint FROM room_file_keys WHERE room_id=$1 FOR UPDATE", [
        id,
      ]);
      requireCondition(
        !old || old.fingerprint === fingerprint,
        409,
        "KEY_IMMUTABLE",
        "The room key cannot be replaced.",
      );
      if (!old)
        await tx.query(
          "INSERT INTO room_file_keys(room_id,fingerprint) VALUES($1,$2)",
          [id, fingerprint],
        );
    });
    res.status(201).json({ fingerprint });
  });
  router.post("/rooms/:id/files", async (req, res) => {
    const rid = roomId.parse(req.params.id),
      v = fileShape.parse(req.body),
      desc = Buffer.from(v.descriptor, "base64"),
      plain = v.encryptedBytes - v.chunkCount * 16;
    requireCondition(
      canonicalB64(v.descriptor) &&
        desc.length > 0 &&
        desc.length <= 8192 &&
        plain >= 0 &&
        plain <= MAX &&
        v.chunkCount === Math.max(1, Math.ceil(plain / CHUNK)),
      422,
      "INVALID_FILE",
      "Shared file metadata is invalid.",
    );
    const result = await db.transaction(
      async (
        tx,
      ): Promise<{
        id: string;
        complete: boolean;
        uploadedChunks: number[];
        receipt?: FileReceipt;
      }> => {
        const r = await locked(tx, rid),
          who = await admit(tx, r, req.ownerId, req.session!.id),
          [key] = await tx.query<{
            fingerprint: string;
          }>("SELECT fingerprint FROM room_file_keys WHERE room_id=$1", [rid]);
        requireCondition(
          key?.fingerprint === v.keyFingerprint,
          409,
          "KEY_MISMATCH",
          "This file uses a different room key.",
        );
        const [old] = await tx.query<{
          id: string;
          room_id: string;
          uploader_id: string;
          descriptor: Buffer;
          chunk_count: number;
          encrypted_bytes: string;
          status: string;
        }>(
          "SELECT id,room_id,uploader_id,descriptor,chunk_count,encrypted_bytes::text,status FROM room_files WHERE id=$1 FOR UPDATE",
          [v.id],
        );
        if (old) {
          requireCondition(
            old.room_id === rid &&
              old.uploader_id === who.uploader &&
              Buffer.from(old.descriptor).equals(desc) &&
              old.chunk_count === v.chunkCount &&
              Number(old.encrypted_bytes) === v.encryptedBytes,
            409,
            "UPLOAD_ID_CONFLICT",
            "This file reference is already in use.",
          );
          const chunks = await tx.query<{
            chunk_index: number;
          }>(
            "SELECT chunk_index FROM room_file_chunks WHERE file_id=$1 ORDER BY chunk_index",
            [v.id],
          );
          const result: {
            id: string;
            complete: boolean;
            uploadedChunks: number[];
            receipt?: FileReceipt;
          } = {
            id: v.id,
            complete: old.status === "complete",
            uploadedChunks: chunks.map((x) => x.chunk_index),
          };
          if (old.status === "complete") {
            const [x] = await tx.query<{
              receipt: FileReceipt;
            }>(
              "SELECT jsonb_build_object('id',id,'acceptedAt',completed_at,'encryptedBytes',encrypted_bytes,'manifestSha256',manifest_sha256) AS receipt FROM room_files WHERE id=$1",
              [v.id],
            );
            result.receipt = x.receipt;
          }
          return result;
        }
        await tx.query(
          "DELETE FROM room_files WHERE room_id=$1 AND uploader_id=$2 AND status='uploading' AND created_at < clock_timestamp()-interval '24 hours'",
          [rid, who.uploader],
        );
        const [usage] = await tx.query<{
          total: string;
        }>(
          "SELECT (COALESCE((SELECT sum(encrypted_bytes) FROM private_submissions WHERE room_id=$1),0)+COALESCE((SELECT sum(encrypted_bytes) FROM room_files WHERE room_id=$1),0))::text AS total",
          [rid],
        );
        requireCondition(
          Number(usage.total) + v.encryptedBytes <= QUOTA,
          413,
          "ROOM_QUOTA",
          "The room has reached its encrypted storage limit.",
        );
        const [counts] = await tx.query<{
          all: number;
          pending: number;
          mine: number;
        }>(
          "SELECT count(*)::int all,count(*) FILTER(WHERE status='uploading')::int pending,count(*) FILTER(WHERE status='uploading' AND uploader_id=$2)::int mine FROM room_files WHERE room_id=$1",
          [rid, who.uploader],
        );
        requireCondition(
          counts.all < 1000,
          413,
          "OBJECT_LIMIT",
          "The room has reached its shared file limit.",
        );
        requireCondition(
          counts.pending < 100 && counts.mine < 10,
          429,
          "UPLOADS_PENDING",
          "Too many uploads are already in progress.",
        );
        const inserted = await tx.query<{
          id: string;
        }>(
          "INSERT INTO room_files(id,room_id,uploader_id,descriptor,chunk_count,encrypted_bytes) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING RETURNING id",
          [v.id, rid, who.uploader, desc, v.chunkCount, v.encryptedBytes],
        );
        requireCondition(
          inserted.length === 1,
          409,
          "UPLOAD_ID_CONFLICT",
          "This file reference is already in use.",
        );
        return { id: v.id, complete: false, uploadedChunks: [] };
      },
    );
    res.status(201).json(result);
  });
  router.put("/rooms/:roomId/files/:fileId/chunks/:index", async (req, res) => {
    const rid = roomId.parse(req.params.roomId),
      fid = roomId.parse(req.params.fileId),
      idx = z.coerce.number().int().min(0).max(249).parse(req.params.index);
    requireCondition(
      Buffer.isBuffer(req.body),
      400,
      "INVALID_CHUNK",
      "Chunk body is required.",
    );
    const bytes = req.body as Buffer;
    let outcome = "stored";
    await db.transaction(async (tx) => {
      const r = await locked(tx, rid),
        who = await admit(tx, r, req.ownerId, req.session!.id),
        [f] = await tx.query<{
          uploader_id: string;
          chunk_count: number;
          encrypted_bytes: string;
          status: string;
        }>(
          "SELECT uploader_id,chunk_count,encrypted_bytes::text,status FROM room_files WHERE id=$1 AND room_id=$2 FOR UPDATE",
          [fid, rid],
        );
      requireCondition(
        f && f.uploader_id === who.uploader,
        404,
        "FILE_NOT_FOUND",
        "File not found.",
      );
      requireCondition(
        f.status === "uploading",
        409,
        "UPLOAD_COMPLETE",
        "File upload is complete.",
      );
      requireCondition(
        idx < f.chunk_count,
        422,
        "INVALID_CHUNK",
        "Chunk index is outside the file.",
      );
      const total = Number(f.encrypted_bytes) - Number(f.chunk_count) * 16,
        expected =
          idx < f.chunk_count - 1
            ? CHUNK + 16
            : total - (f.chunk_count - 1) * CHUNK + 16;
      requireCondition(
        bytes.length === expected,
        422,
        "INVALID_CHUNK",
        "Chunk size does not match the declared file.",
      );
      const [existing] = await tx.query<{
        ciphertext: Buffer;
      }>(
        "SELECT ciphertext FROM room_file_chunks WHERE file_id=$1 AND chunk_index=$2",
        [fid, idx],
      );
      if (existing) {
        requireCondition(
          Buffer.from(existing.ciphertext).equals(bytes),
          409,
          "CHUNK_CONFLICT",
          "This chunk index already contains different ciphertext.",
        );
        outcome = "retry";
        return;
      }
      const [last] = await tx.query<{
        n: number;
      }>(
        "SELECT COALESCE(max(chunk_index),-1)::int n FROM room_file_chunks WHERE file_id=$1",
        [fid],
      );
      requireCondition(
        idx === last.n + 1,
        409,
        "CHUNK_ORDER",
        "Upload chunks in order.",
      );
      await tx.query(
        "INSERT INTO room_file_chunks(file_id,chunk_index,ciphertext,sha256) VALUES($1,$2,$3,$4)",
        [fid, idx, bytes, hash(bytes)],
      );
    });
    res.status(200).json({ uploaded: true, retry: outcome === "retry" });
  });
  router.post("/rooms/:roomId/files/:fileId/complete", async (req, res) => {
    const rid = roomId.parse(req.params.roomId);
    const fid = roomId.parse(req.params.fileId);
    const manifest = z
      .string()
      .regex(/^[0-9a-f]{64}$/)
      .parse(
        z.object({ manifestSha256: z.string() }).strict().parse(req.body)
          .manifestSha256,
      );
    let receipt: FileReceipt | undefined;
    await db.transaction(async (tx) => {
      const r = await locked(tx, rid),
        who = await admit(tx, r, req.ownerId, req.session!.id);
      const [f] = await tx.query<{
        uploader_id: string;
        status: string;
        chunk_count: number;
        encrypted_bytes: string;
        descriptor: Buffer;
        manifest_sha256: string | null;
        completed_at: Date | null;
      }>(
        "SELECT uploader_id,status,chunk_count,encrypted_bytes::text,descriptor,manifest_sha256,completed_at FROM room_files WHERE id=$1 AND room_id=$2 FOR UPDATE",
        [fid, rid],
      );
      requireCondition(
        f && f.uploader_id === who.uploader,
        404,
        "FILE_NOT_FOUND",
        "File not found.",
      );
      if (f.status === "complete") {
        requireCondition(
          f.manifest_sha256 === manifest,
          409,
          "MANIFEST_CONFLICT",
          "This file was completed with another manifest.",
        );
        receipt = {
          id: fid,
          acceptedAt: f.completed_at!,
          encryptedBytes: Number(f.encrypted_bytes),
          manifestSha256: manifest,
        };
        return;
      }
      const [count] = await tx.query<{
        count: number;
        bytes: string;
      }>(
        "SELECT count(*)::int count,COALESCE(sum(octet_length(ciphertext)),0)::text bytes FROM room_file_chunks WHERE file_id=$1",
        [fid],
      );
      requireCondition(
        count.count === f.chunk_count &&
          Number(count.bytes) === Number(f.encrypted_bytes),
        409,
        "CHUNKS_INCOMPLETE",
        "Upload all chunks before completing.",
      );
      const digest = createHash("sha256").update(Buffer.from(f.descriptor));
      for (let i = 0; i < f.chunk_count; i++) {
        const [chunk] = await tx.query<{
          sha256: string;
          ciphertext: Buffer;
        }>(
          "SELECT sha256,ciphertext FROM room_file_chunks WHERE file_id=$1 AND chunk_index=$2",
          [fid, i],
        );
        requireCondition(
          chunk && hash(Buffer.from(chunk.ciphertext)) === chunk.sha256,
          409,
          "CHUNK_CORRUPT",
          "An uploaded chunk failed its integrity check.",
        );
        digest.update(Buffer.from(chunk.sha256, "hex"));
      }
      const actual = digest.digest("hex");
      requireCondition(
        actual === manifest,
        422,
        "MANIFEST_MISMATCH",
        "The file manifest does not match its encrypted chunks.",
      );
      const [fresh] = await tx.query<{
        status: string;
        expired: boolean;
      }>(
        "SELECT status,expires_at<=clock_timestamp() AS expired FROM rooms WHERE id=$1",
        [rid],
      );
      requireCondition(
        fresh.status === "open" && !fresh.expired,
        410,
        "ROOM_CLOSED",
        "This room is no longer accepting shared files.",
      );
      const [stamp] = await tx.query<{
        completed_at: Date;
      }>(
        "UPDATE room_files SET status='complete',manifest_sha256=$2,completed_at=clock_timestamp() WHERE id=$1 RETURNING completed_at",
        [fid, manifest],
      );
      receipt = {
        id: fid,
        acceptedAt: stamp.completed_at,
        encryptedBytes: Number(f.encrypted_bytes),
        manifestSha256: manifest,
      };
    });
    res.json({ receipt });
  });
  router.get("/rooms/:id/files", async (req, res) => {
    const rid = roomId.parse(req.params.id),
      r = await getRoom(db, rid);
    await admit(db, r, req.ownerId, req.session!.id);
    let cursor: {
      createdAt: string;
      id: string;
    } | null = null;
    if (req.query.before !== undefined) {
      const raw = z.string().base64url().max(200).parse(req.query.before);
      try {
        cursor = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as {
          createdAt: string;
          id: string;
        };
      } catch {
        requireCondition(
          false,
          422,
          "INVALID_CURSOR",
          "File page cursor is invalid.",
        );
      }
      requireCondition(
        Boolean(
          cursor &&
          /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(cursor.createdAt) &&
          /^[0-9a-f-]{36}$/.test(cursor.id),
        ),
        422,
        "INVALID_CURSOR",
        "File page cursor is invalid.",
      );
    }
    type FileRow = {
      id: string;
      descriptor: Buffer;
      chunk_count: number;
      encrypted_bytes: string;
      manifest_sha256: string;
      created_at: Date;
      created_at_cursor: string;
      receipt: FileReceipt;
      can_delete: boolean;
    };
    const rows = await db.query<FileRow>(
      `SELECT f.id,f.descriptor,f.chunk_count,f.encrypted_bytes::text,
    f.manifest_sha256,f.created_at,
    to_char(f.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
    jsonb_build_object('id',f.id,'acceptedAt',f.completed_at,'encryptedBytes',f.encrypted_bytes,'manifestSha256',f.manifest_sha256) receipt,
    (f.uploader_id=$2) can_delete FROM room_files f WHERE f.room_id=$1 AND f.status='complete'
    AND ($3::timestamptz IS NULL OR (f.created_at,f.id)<($3::timestamptz,$4::uuid))
    ORDER BY f.created_at DESC,f.id DESC LIMIT 51`,
      [rid, req.session!.id, cursor?.createdAt ?? null, cursor?.id ?? null],
    );
    const page = rows.slice(0, 50),
      last = page.at(-1);
    const activeFiles = await db.query<{ id: string }>(
      "SELECT id FROM room_files WHERE room_id=$1 AND status='complete' ORDER BY created_at DESC,id DESC",
      [rid],
    );
    res.json({
      activeIds: activeFiles.map((file) => file.id),
      files: page.map((x) => ({
        id: x.id,
        descriptor: Buffer.from(x.descriptor).toString("base64"),
        chunkCount: x.chunk_count,
        encryptedBytes: Number(x.encrypted_bytes),
        manifestSha256: x.manifest_sha256,
        createdAt: x.created_at,
        receipt: x.receipt,
        canDelete: x.can_delete || r.owner_id === req.ownerId,
      })),
      nextCursor:
        rows.length > 50 && last
          ? Buffer.from(
              JSON.stringify({
                createdAt: last.created_at_cursor,
                id: last.id,
              }),
            ).toString("base64url")
          : null,
    });
  });
  router.get("/rooms/:roomId/files/:fileId/chunks/:index", async (req, res) => {
    const rid = roomId.parse(req.params.roomId),
      fid = roomId.parse(req.params.fileId),
      idx = z.coerce.number().int().min(0).max(249).parse(req.params.index),
      r = await getRoom(db, rid);
    await admit(db, r, req.ownerId, req.session!.id);
    const [c] = await db.query<{
      ciphertext: Buffer;
      sha256: string;
    }>(
      "SELECT c.ciphertext,c.sha256 FROM room_file_chunks c JOIN room_files f ON f.id=c.file_id WHERE f.id=$1 AND f.room_id=$2 AND f.status='complete' AND c.chunk_index=$3",
      [fid, rid, idx],
    );
    requireCondition(c, 404, "FILE_NOT_FOUND", "File not found.");
    const ciphertext = Buffer.from(c.ciphertext);
    requireCondition(
      hash(ciphertext) === c.sha256,
      500,
      "FILE_CORRUPT",
      "Stored file ciphertext failed its integrity check.",
    );
    res
      .setHeader("X-Ciphertext-SHA256", c.sha256)
      .type("application/octet-stream")
      .setHeader("Content-Length", ciphertext.length)
      .send(ciphertext);
  });
  router.delete("/rooms/:roomId/files/:fileId", async (req, res) => {
    const rid = roomId.parse(req.params.roomId),
      fid = roomId.parse(req.params.fileId);
    await db.transaction(async (tx) => {
      const r = await locked(tx, rid),
        who = await admit(tx, r, req.ownerId, req.session!.id),
        [f] = await tx.query<{
          uploader_id: string;
        }>(
          "SELECT uploader_id FROM room_files WHERE id=$1 AND room_id=$2 FOR UPDATE",
          [fid, rid],
        );
      if (!f) return;
      requireCondition(
        r.owner_id === req.ownerId || f.uploader_id === who.uploader,
        403,
        "OWNER_REQUIRED",
        "You cannot delete this shared file.",
      );
      await tx.query("DELETE FROM room_files WHERE id=$1", [fid]);
    });
    res.status(204).end();
  });
  return router;
}
