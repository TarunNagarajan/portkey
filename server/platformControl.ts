import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { isIP } from "node:net";
import { Router } from "express";
import { z } from "zod";
import type { Database } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import { platformContractDigest, customContractDigest, GROTH16_ADAPTER } from "../shared/platform.js";
import { parseVerificationKey, validateVerificationKeyBounded } from "./groth16Verifier.js";
import { fetchDomainVerificationFile } from "./domainVerification.js";
import { canonicalUuid, versionInput } from "./platformProtocol.js";

const hash = (value: string) => createHash("sha256").update(value).digest();
const id = canonicalUuid;
const contractInput = z
  .object({
    name: z.string().trim().min(1).max(100),
    issuerLabel: z.string().trim().min(1).max(100),
    description: z.string().max(500),
    adapter: z.enum(["semaphore-membership-v1", GROTH16_ADAPTER]).default("semaphore-membership-v1"),
    groupIds: z.array(id).max(4).optional(),
    verificationKey: z.unknown().optional(),
    publicSignalNames: z.unknown().optional(),
  })
  .strict();

function contractPolicy(input: z.infer<typeof contractInput>, contractId: string, version: number, customConfig?: ReturnType<typeof parseVerificationKey>) {
  if (input.adapter === GROTH16_ADAPTER) {
    requireCondition(!input.groupIds || input.groupIds.length === 0, 422, "INVALID_GROUPS", "Custom Groth16 contracts do not use credential groups.");
    const config = customConfig ?? parseVerificationKey(input.verificationKey, input.publicSignalNames);
    return { groups: [] as string[], config, digest: customContractDigest(contractId, version, config) };
  }
  requireCondition(input.verificationKey === undefined && input.publicSignalNames === undefined, 422, "INVALID_ADAPTER", "Choose a supported proof adapter.");
  const rawGroups = input.groupIds ?? [];
  requireCondition(rawGroups.length >= 1, 422, "INVALID_GROUPS", "Choose at least one credential group.");
  const groups = [...new Set(rawGroups.map(value => value.toLowerCase()))].sort();
  requireCondition(groups.length === rawGroups.length, 422, "INVALID_GROUPS", "Choose distinct credential groups.");
  return { groups, config: null, digest: platformContractDigest(contractId, version, groups) };
}
const appInput = z
  .object({
    name: z.string().trim().min(1).max(100),
    origin: z.string().max(300),
    redirectUris: z.array(z.string().max(500)).min(1).max(3),
  })
  .strict();
const pinsInput = z
  .object({
    contracts: z
      .array(z.object({ contractId: id, version: versionInput }).strict())
      .max(10),
  })
  .strict();

export function platformControlRoutes(
  database: Database,
  options: { origin: string; secure: boolean },
) {
  const router = Router();
  router.get("/platform/contracts", async (request, response) => {
    const rows = await database.query(
      "SELECT id,name,issuer_label,created_at FROM platform_contracts WHERE owner_session_id=$1 ORDER BY created_at DESC LIMIT 32",
      [request.ownerId!],
    );
    response.json({ contracts: rows });
  });
  router.post("/platform/contracts", async (request, response) => {
    const input = contractInput.parse(request.body);
    const customConfig = input.adapter === GROTH16_ADAPTER ? parseVerificationKey(input.verificationKey, input.publicSignalNames) : undefined;
    if (customConfig) await validateVerificationKeyBounded(customConfig);
    const result = await database.transaction(async (tx) => {
      await tx.query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE", [
        request.ownerId!,
      ]);
      const [owner] = await tx.query<{ available: boolean }>(
        "SELECT available FROM owner_authorities WHERE id=$1",
        [request.ownerId!],
      );
      requireCondition(
        owner?.available,
        401,
        "SESSION_EXPIRED",
        "Your session has expired.",
      );
      const [count] = await tx.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM platform_contracts WHERE owner_session_id=$1",
        [request.ownerId!],
      );
      requireCondition(
        count.total < 32,
        409,
        "CONTRACT_LIMIT",
        "This session has reached its contract limit.",
      );
      const contractId = randomUUID();
      const policy = contractPolicy(input, contractId, 1, customConfig);
      const groups = policy.groups;
      const owned = await tx.query<{ id: string; name: string }>(
        `SELECT g.id,g.name FROM credential_groups g JOIN owner_authorities s ON s.id=g.owner_session_id
        WHERE g.id=ANY($1::uuid[]) AND g.owner_session_id=$2 AND s.available ORDER BY g.id FOR UPDATE OF g`,
        [groups, request.ownerId!],
      );
      requireCondition(
        input.adapter === GROTH16_ADAPTER || owned.length === groups.length,
        403,
        "GROUP_NOT_OWNED",
        "Each contract group must belong to this issuer session.",
      );
      await tx.query(
        "INSERT INTO platform_contracts(id,owner_session_id,name,issuer_label) VALUES($1,$2,$3,$4)",
        [contractId, request.ownerId!, input.name, input.issuerLabel],
      );
      const digest = policy.digest;
      await tx.query(
        "INSERT INTO platform_contract_versions(contract_id,version,description,group_ids,digest,adapter,proof_depth,adapter_config) VALUES($1,1,$2,$3,$4,$5,$6,$7)",
        [contractId, input.description, groups, digest, input.adapter, input.adapter === GROTH16_ADAPTER ? null : 10, policy.config],
      );
      return { id: contractId, version: 1, digest, groups: owned, adapter: input.adapter, adapterConfig: policy.config };
    });
    response.status(201).json(result);
  });
  router.get(
    "/platform/contracts/:contractId/versions",
    async (request, response) => {
      const contractId = id.parse(request.params.contractId);
      const [owned] = await database.query(
        "SELECT id FROM platform_contracts WHERE id=$1 AND owner_session_id=$2",
        [contractId, request.ownerId!],
      );
      requireCondition(owned, 404, "CONTRACT_NOT_FOUND", "Contract not found.");
      const versions = await database.query(
        "SELECT version,description,group_ids,digest,adapter,proof_depth,adapter_config,published_at,retired_at FROM platform_contract_versions WHERE contract_id=$1 ORDER BY version DESC",
        [contractId],
      );
      response.json({ versions });
    },
  );
  router.post(
    "/platform/contracts/:contractId/versions",
    async (request, response) => {
      const contractId = id.parse(request.params.contractId);
      const input = contractInput
        .pick({ description: true, adapter: true, groupIds: true, verificationKey: true, publicSignalNames: true })
        .parse(request.body);
      const customConfig = input.adapter === GROTH16_ADAPTER ? parseVerificationKey(input.verificationKey, input.publicSignalNames) : undefined;
      if (customConfig) await validateVerificationKeyBounded(customConfig);
      const result = await database.transaction(async (tx) => {
        const [contract] = await tx.query<{ id: string }>(
          "SELECT id FROM platform_contracts WHERE id=$1 AND owner_session_id=$2 FOR UPDATE",
          [contractId, request.ownerId!],
        );
        requireCondition(
          contract,
          404,
          "CONTRACT_NOT_FOUND",
          "Contract not found.",
        );
        const [count] = await tx.query<{ total: number; version: number }>(
          "SELECT count(*)::int AS total, COALESCE(max(version),0)::int AS version FROM platform_contract_versions WHERE contract_id=$1",
          [contractId],
        );
        requireCondition(
          count.total < 20,
          409,
          "VERSION_LIMIT",
          "This contract has reached its version limit.",
        );
        const version = count.version + 1;
        const policy = contractPolicy(input as z.infer<typeof contractInput>, contractId, version, customConfig);
        const groups = policy.groups;
        const owned = await tx.query<{ id: string; name: string }>(
          `SELECT g.id,g.name FROM credential_groups g JOIN owner_authorities s ON s.id=g.owner_session_id
        WHERE g.id=ANY($1::uuid[]) AND g.owner_session_id=$2 AND s.available ORDER BY g.id FOR UPDATE OF g`,
          [groups, request.ownerId!],
        );
        requireCondition(input.adapter === GROTH16_ADAPTER || owned.length === groups.length, 403, "GROUP_NOT_OWNED", "Each contract group must belong to this issuer session.");
        const digest = policy.digest;
        await tx.query(
          "INSERT INTO platform_contract_versions(contract_id,version,description,group_ids,digest,adapter,proof_depth,adapter_config) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
          [contractId, version, input.description, groups, digest, input.adapter, input.adapter === GROTH16_ADAPTER ? null : 10, policy.config],
        );
        return { contractId, version, digest, groups: owned, adapter: input.adapter, adapterConfig: policy.config };
      });
      response.status(201).json(result);
    },
  );
  router.post(
    "/platform/contracts/:contractId/versions/:version/retire",
    async (request, response) => {
      const contractId = id.parse(request.params.contractId);
      const version = versionInput.parse(Number(request.params.version));
      await database.transaction(async (tx) => {
        const [contract] = await tx.query<{ id: string }>(
          "SELECT id FROM platform_contracts WHERE id=$1 AND owner_session_id=$2 FOR UPDATE",
          [contractId, request.ownerId!],
        );
        requireCondition(
          contract,
          404,
          "CONTRACT_NOT_FOUND",
          "Contract not found.",
        );
        const [retired] = await tx.query(
          "UPDATE platform_contract_versions SET retired_at=COALESCE(retired_at,clock_timestamp()) WHERE contract_id=$1 AND version=$2 RETURNING version",
          [contractId, version],
        );
        requireCondition(
          retired,
          404,
          "CONTRACT_VERSION_NOT_FOUND",
          "Contract version not found.",
        );
      });
      response.json({ retired: true });
    },
  );
  router.get("/platform/apps", async (request, response) => {
    const apps = await database.query(
      `SELECT a.id,a.name,a.origin,a.redirect_uris,a.key_generation,a.disabled_at,a.domain_verified_at,a.created_at,
      COALESCE(json_agg(json_build_object('contract_id',t.contract_id,'contract_version',t.contract_version)
        ORDER BY t.contract_id,t.contract_version) FILTER (WHERE t.app_id IS NOT NULL),'[]') AS contracts
      FROM platform_apps a LEFT JOIN platform_app_trust t ON t.app_id=a.id
      WHERE a.owner_session_id=$1 GROUP BY a.id ORDER BY a.created_at DESC LIMIT 10`,
      [request.ownerId!],
    );
    response.json({ apps });
  });
  router.post("/platform/apps", async (request, response) => {
    const input = appInput.parse(request.body);
    let origin: string;
    try {
      const url = new URL(input.origin);
      const localHost =
        url.hostname === "localhost" ||
        url.hostname.endsWith(".localhost") ||
        url.hostname === "127.0.0.1" ||
        url.hostname === "[::1]";
      const publicHttpsOrigin =
        url.protocol === "https:" &&
        !url.port &&
        !isIP(url.hostname) &&
        url.hostname.includes(".");
      if (
        (publicHttpsOrigin ||
          (!options.secure && localHost && url.protocol === "http:")) &&
        !url.username &&
        !url.password &&
        url.pathname === "/" &&
        !url.search &&
        !url.hash &&
        url.origin === input.origin
      )
        origin = url.origin;
      else throw new Error();
    } catch {
      throw new HttpError(
        422,
        "INVALID_ORIGIN",
        "Use an exact HTTPS origin (HTTP is allowed only for local development).",
      );
    }
    requireCondition(
      origin !== options.origin,
      422,
      "WALLET_ORIGIN",
      "The application must use a different origin from Portkey.",
    );
    const redirects = [...new Set(input.redirectUris)];
    requireCondition(
      redirects.length === input.redirectUris.length,
      422,
      "INVALID_REDIRECT",
      "Redirect addresses must be distinct.",
    );
    for (const item of redirects) {
      let uri: URL;
      try {
        uri = new URL(item);
      } catch {
        throw new HttpError(
          422,
          "INVALID_REDIRECT",
          "A return address is invalid.",
        );
      }
      requireCondition(
        uri.origin === origin &&
          !uri.username &&
          !uri.password &&
          !uri.search &&
          !uri.hash,
        422,
        "INVALID_REDIRECT",
        "Return addresses must be on the registered origin with no credentials, query, or fragment.",
      );
    }
    const secret = randomBytes(32).toString("base64url");
    const appId = randomUUID();
    await database.transaction(async (tx) => {
      await tx.query("SELECT id FROM sessions WHERE id=$1 FOR UPDATE", [
        request.ownerId!,
      ]);
      const [owner] = await tx.query<{ active: boolean }>(
        "SELECT available AS active FROM owner_authorities WHERE id=$1",
        [request.ownerId!],
      );
      requireCondition(
        owner?.active,
        401,
        "SESSION_EXPIRED",
        "Your session has expired.",
      );
      const [count] = await tx.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM platform_apps WHERE owner_session_id=$1",
        [request.ownerId!],
      );
      requireCondition(
        count.total < 10,
        409,
        "APP_LIMIT",
        "This session has reached its application limit.",
      );
      await tx.query(
        "INSERT INTO platform_apps(id,owner_session_id,name,origin,redirect_uris,key_digest) VALUES($1,$2,$3,$4,$5,$6)",
        [appId, request.ownerId!, input.name, origin, redirects, hash(secret)],
      );
    });
    response.status(201).json({
      id: appId,
      name: input.name,
      origin,
      redirectUris: redirects,
      apiKey: `pk_live_${secret}`,
    });
  });
  router.put("/platform/apps/:appId/trust", async (request, response) => {
    const appId = id.parse(request.params.appId);
    const { contracts } = pinsInput.parse(request.body);
    await database.transaction(async (tx) => {
      const [app] = await tx.query<{ id: string }>(
        "SELECT id FROM platform_apps WHERE id=$1 AND owner_session_id=$2 FOR UPDATE",
        [appId, request.ownerId!],
      );
      requireCondition(app, 404, "APP_NOT_FOUND", "Application not found.");
      const seen = new Set<string>();
      for (const pin of contracts) {
        const key = `${pin.contractId}:${pin.version}`;
        requireCondition(
          !seen.has(key),
          422,
          "DUPLICATE_TRUST",
          "Choose each contract version once.",
        );
        seen.add(key);
        const [version] = await tx.query(
          "SELECT 1 FROM platform_contract_versions WHERE contract_id=$1 AND version=$2 AND retired_at IS NULL",
          [pin.contractId, pin.version],
        );
        requireCondition(
          version,
          422,
          "CONTRACT_UNAVAILABLE",
          "Choose a published, available contract version.",
        );
      }
      const currentPins = await tx.query<{
        contract_id: string;
        contract_version: number;
      }>(
        "SELECT contract_id,contract_version FROM platform_app_trust WHERE app_id=$1 FOR UPDATE",
        [appId],
      );
      const currentKeys = new Set(
        currentPins.map((pin) => `${pin.contract_id}:${pin.contract_version}`),
      );
      const wantedKeys = new Set(
        contracts.map((pin) => `${pin.contractId}:${pin.version}`),
      );
      for (const pin of currentPins) {
        const key = `${pin.contract_id}:${pin.contract_version}`;
        if (!wantedKeys.has(key))
          await tx.query(
            "DELETE FROM platform_app_trust WHERE app_id=$1 AND contract_id=$2 AND contract_version=$3",
            [appId, pin.contract_id, pin.contract_version],
          );
      }
      for (const pin of contracts) {
        const key = `${pin.contractId}:${pin.version}`;
        if (!currentKeys.has(key))
          await tx.query(
            "INSERT INTO platform_app_trust(app_id,contract_id,contract_version) VALUES($1,$2,$3)",
            [appId, pin.contractId, pin.version],
          );
      }
    });
    response.json({ saved: true });
  });
  router.get("/platform/apps/:appId/trust", async (request, response) => {
    const appId = id.parse(request.params.appId);
    const [app] = await database.query(
      "SELECT id FROM platform_apps WHERE id=$1 AND owner_session_id=$2",
      [appId, request.ownerId!],
    );
    requireCondition(app, 404, "APP_NOT_FOUND", "Application not found.");
    const contracts = await database.query(
      "SELECT contract_id,contract_version FROM platform_app_trust WHERE app_id=$1 ORDER BY contract_id,contract_version",
      [appId],
    );
    response.json({ contracts });
  });
  router.post(
    "/platform/apps/:appId/domain-challenge",
    async (request, response) => {
      const appId = id.parse(request.params.appId);
      const challenge = randomBytes(32).toString("base64url");
      const [app] = await database.query<{ origin: string }>(
        `UPDATE platform_apps SET domain_challenge_digest=$3, domain_challenge_expires_at=clock_timestamp()+interval '15 minutes'
      WHERE id=$1 AND owner_session_id=$2 AND disabled_at IS NULL RETURNING origin`,
        [appId, request.ownerId!, hash(challenge)],
      );
      requireCondition(app, 404, "APP_NOT_FOUND", "Application not found.");
      response.json({
        appId,
        challenge,
        url: new URL("/.well-known/portkey-app.json", app.origin).toString(),
        expiresInSeconds: 900,
      });
    },
  );
  router.post(
    "/platform/apps/:appId/verify-domain",
    async (request, response) => {
      const appId = id.parse(request.params.appId);
      z.object({})
        .strict()
        .parse(request.body ?? {});
      const [snapshot] = await database.query<{
        origin: string;
        challenge_digest: Buffer | null;
        challenge_expires_at: Date | null;
        active: boolean;
      }>(
        `SELECT a.origin,a.domain_challenge_digest AS challenge_digest,a.domain_challenge_expires_at AS challenge_expires_at,
      a.domain_challenge_expires_at>clock_timestamp() AND s.available AS active
      FROM platform_apps a JOIN owner_authorities s ON s.id=a.owner_session_id WHERE a.id=$1 AND a.owner_session_id=$2 AND a.disabled_at IS NULL`,
        [appId, request.ownerId!],
      );
      requireCondition(
        snapshot?.challenge_digest && snapshot.active,
        409,
        "CHALLENGE_EXPIRED",
        "Create a fresh domain check and try again.",
      );
      let document: unknown;
      try {
        document = await fetchDomainVerificationFile(
          snapshot.origin,
          !options.secure,
        );
      } catch {
        throw new HttpError(
          422,
          "DOMAIN_CHECK_FAILED",
          "Portkey could not confirm the verification file at this application address.",
        );
      }
      const [current] = await database.transaction(async (tx) => {
        const [locked] = await tx.query<{
          origin: string;
          challenge_digest: Buffer | null;
          challenge_expires_at: Date | null;
          active: boolean;
        }>(
          `SELECT a.origin,a.domain_challenge_digest AS challenge_digest,a.domain_challenge_expires_at AS challenge_expires_at,
        a.domain_challenge_expires_at>clock_timestamp() AND s.available AS active
        FROM platform_apps a JOIN owner_authorities s ON s.id=a.owner_session_id WHERE a.id=$1 AND a.owner_session_id=$2 AND a.disabled_at IS NULL FOR UPDATE OF a`,
          [appId, request.ownerId!],
        );
        requireCondition(
          locked &&
            locked.active &&
            locked.origin === snapshot.origin &&
            locked.challenge_digest &&
            snapshot.challenge_digest &&
            timingSafeEqual(locked.challenge_digest, snapshot.challenge_digest),
          409,
          "CHALLENGE_CHANGED",
          "The domain check changed or expired. Create a fresh check.",
        );
        const parsedDocument = z
          .object({
            appId: canonicalUuid,
            challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
          })
          .strict()
          .safeParse(document);
        requireCondition(
          parsedDocument.success &&
            parsedDocument.data.appId === appId &&
            timingSafeEqual(
              hash(parsedDocument.data.challenge),
              locked.challenge_digest,
            ),
          422,
          "DOMAIN_CHECK_FAILED",
          "The verification file does not match this application.",
        );
        return tx.query(
          "UPDATE platform_apps SET domain_verified_at=clock_timestamp(),domain_challenge_digest=NULL,domain_challenge_expires_at=NULL WHERE id=$1 RETURNING id",
          [appId],
        );
      });
      response.json({ verified: Boolean(current) });
    },
  );
  router.post("/platform/apps/:appId/rotate-key", async (request, response) => {
    const appId = id.parse(request.params.appId);
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const secret = randomBytes(32).toString("base64url");
    const [app] = await database.query<{ id: string; key_generation: number }>(
      "UPDATE platform_apps SET key_digest=$3,key_generation=key_generation+1 WHERE id=$1 AND owner_session_id=$2 AND disabled_at IS NULL RETURNING id,key_generation",
      [appId, request.ownerId!, hash(secret)],
    );
    requireCondition(app, 404, "APP_NOT_FOUND", "Application not found.");
    response.json({
      apiKey: `pk_live_${secret}`,
      keyGeneration: app.key_generation,
    });
  });
  router.post("/platform/apps/:appId/disable", async (request, response) => {
    const appId = id.parse(request.params.appId);
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const [app] = await database.query(
      "UPDATE platform_apps SET disabled_at=COALESCE(disabled_at,clock_timestamp()),key_generation=key_generation+1 WHERE id=$1 AND owner_session_id=$2 RETURNING id",
      [appId, request.ownerId!],
    );
    requireCondition(app, 404, "APP_NOT_FOUND", "Application not found.");
    response.json({ disabled: true });
  });
  router.get("/platform/apps/:appId/history", async (request, response) => {
    const appId = id.parse(request.params.appId);
    const limit = z.coerce
      .number()
      .int()
      .min(1)
      .max(50)
      .default(25)
      .parse(request.query.limit);
    const cursorSchema = z.string().max(256).optional();
    const cursor = cursorSchema.parse(request.query.cursor);
    const [app] = await database.query(
      "SELECT id FROM platform_apps WHERE id=$1 AND owner_session_id=$2",
      [appId, request.ownerId!],
    );
    requireCondition(app, 404, "APP_NOT_FOUND", "Application not found.");
    let before: { createdAt: string; id: string } | undefined;
    if (cursor) {
      try {
        const parsed = JSON.parse(
          Buffer.from(cursor, "base64url").toString("utf8"),
        ) as unknown;
        before = z
          .object({ createdAt: z.iso.datetime(), id: id })
          .strict()
          .parse(parsed);
        requireCondition(
          Buffer.from(cursor, "base64url").toString("base64url") === cursor,
          400,
          "INVALID_CURSOR",
          "The request history cursor is invalid.",
        );
      } catch {
        throw new HttpError(
          400,
          "INVALID_CURSOR",
          "The request history cursor is invalid.",
        );
      }
    }
    const rows = await database.query<{
      id: string;
      contract_id: string;
      contract_version: number;
      status: string;
      created_at: Date;
      expires_at: Date;
      verified_at: Date | null;
    }>(
      `SELECT id,contract_id,contract_version,status,created_at,expires_at,verified_at FROM platform_requests
       WHERE app_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)<($2::timestamptz,$3::uuid))
       ORDER BY created_at DESC,id DESC LIMIT $4`,
      [appId, before?.createdAt ?? null, before?.id ?? null, limit + 1],
    );
    const hasMore = rows.length > limit;
    const page = rows.slice(0, limit);
    const last = page.at(-1);
    const nextCursor =
      hasMore && last
        ? Buffer.from(
            JSON.stringify({
              createdAt: last.created_at.toISOString(),
              id: last.id,
            }),
          ).toString("base64url")
        : null;
    response.json({ requests: page, nextCursor });
  });
  return router;
}
