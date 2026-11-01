import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import type { Database } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import {
  publicJwks,
  pkceS256,
  signCompactJws,
  signingKey,
} from "./platformCrypto.js";
import {
  appAuth,
  appCurrent,
  canonicalUuid,
  createInput,
  exchangeInput,
  hash,
  lockRequestAuthority,
  trustedContract,
  versionInput,
} from "./platformProtocol.js";

export function platformPublicRoutes(database: Database, origin: string) {
  const router = Router();
  router.get("/.well-known/jwks.json", async (_request, response) => {
    response.setHeader("Cache-Control", "public, max-age=300");
    response.json(await publicJwks(database));
  });
  router.get(
    "/contracts/:contractId/versions/:version",
    async (request, response) => {
      const contractId = canonicalUuid.parse(request.params.contractId);
      const version = versionInput.parse(Number(request.params.version));
      const [row] = await database.query<{
        contract_id: string;
        version: number;
        description: string;
        group_ids: string[];
        adapter: string;
        proof_depth: number | null;
        adapter_config: unknown;
        digest: string;
        retired_at: Date | null;
        published_at: Date;
        issuer_label: string;
        contract_name: string;
        available: boolean;
        names: string[];
      }>(
        `SELECT v.contract_id,v.version,v.description,v.group_ids,v.digest,v.adapter,v.proof_depth,v.adapter_config,v.retired_at,v.published_at,c.issuer_label,c.name AS contract_name,
       s.available AS available,ARRAY(SELECT g.name FROM credential_groups g WHERE g.id=ANY(v.group_ids) ORDER BY g.id) AS names
       FROM platform_contract_versions v JOIN platform_contracts c ON c.id=v.contract_id JOIN owner_authorities s ON s.id=c.owner_session_id WHERE v.contract_id=$1 AND v.version=$2`,
        [contractId, version],
      );
      requireCondition(
        row,
        404,
        "CONTRACT_NOT_FOUND",
        "Contract version not found.",
      );
      response.json({
        contractId: row.contract_id,
        version: row.version,
        name: row.contract_name,
        issuerLabel: row.issuer_label,
        description: row.description,
        groups: row.group_ids.map((groupId, index) => ({
          id: groupId,
          name: row.names[index] ?? "Unavailable group",
        })),
        digest: row.digest,
        adapter: row.adapter,
        proofDepth: row.proof_depth,
        adapterConfig: row.adapter_config,
        available: row.available && !row.retired_at,
        publishedAt: row.published_at.toISOString(),
        portkeyOrigin: origin,
      });
    },
  );
  return router;
}

export function platformAppApiRoutes(database: Database, origin: string) {
  const router = Router();
  const authorize = appAuth(database);
  const appWriteLimit = rateLimit({
    windowMs: 60_000,
    limit: 60,
    keyGenerator: (request) =>
      request.platformApp?.id ?? ipKeyGenerator(request.ip ?? "127.0.0.1"),
    standardHeaders: "draft-8",
    legacyHeaders: false,
  });
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });
  router.use(
    rateLimit({
      windowMs: 60_000,
      limit: 30,
      keyGenerator: (request) => ipKeyGenerator(request.ip ?? "127.0.0.1"),
      standardHeaders: "draft-8",
      legacyHeaders: false,
    }),
  );
  router.post(
    "/proof-requests",
    authorize,
    appWriteLimit,
    async (request, response) => {
      const app = request.platformApp!;
      const input = createInput.parse(request.body);
      requireCondition(
        input.state !== input.codeChallenge,
        422,
        "INVALID_FLOW",
        "State and code challenge must be separate random values.",
      );
      let uri: URL;
      try {
        uri = new URL(input.redirectUri);
      } catch {
        throw new HttpError(
          422,
          "INVALID_REDIRECT",
          "The return address is not registered.",
        );
      }
      requireCondition(
        app.origin === uri.origin &&
          !uri.username &&
          !uri.password &&
          !uri.search &&
          !uri.hash,
        422,
        "INVALID_REDIRECT",
        "The return address is not registered.",
      );
      const requestId = randomUUID();
      const capability = randomBytes(32).toString("base64url");
      const row = await database.transaction(async (tx) => {
        const appRow = await appCurrent(tx, app);
        const contract = await trustedContract(
          tx,
          app.id,
          input.contractId,
          input.contractVersion,
        );
        requireCondition(
          appRow.origin === uri.origin,
          422,
          "INVALID_REDIRECT",
          "The return address is not registered.",
        );
        const [redirect] = await tx.query(
          "SELECT 1 FROM platform_apps WHERE id=$1 AND $2=ANY(redirect_uris)",
          [app.id, input.redirectUri],
        );
        requireCondition(
          redirect,
          422,
          "INVALID_REDIRECT",
          "The return address is not registered.",
        );
        const [quota] = await tx.query<{ total: number; lifetime: number }>(
          `SELECT count(*) FILTER(WHERE expires_at>clock_timestamp() AND status IN ('pending','verified'))::int AS total,
        count(*)::int AS lifetime FROM platform_requests WHERE app_id=$1`,
          [app.id],
        );
        requireCondition(
          quota.total < 1000 && quota.lifetime < 10000,
          429,
          "REQUEST_LIMIT",
          "This application has reached its proof request limit.",
        );
        const [stored] = await tx.query<{ expires_at: Date }>(
          `INSERT INTO platform_requests(id,app_id,key_generation,contract_id,contract_version,trust_revision,redirect_uri,state,state_digest,code_challenge,capability_digest,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,LEAST(
          clock_timestamp()+interval '5 minutes',
          (SELECT owner.expires_at FROM platform_apps a JOIN owner_authorities owner ON owner.id=a.owner_session_id WHERE a.id=$2),
          (SELECT issuer.expires_at FROM platform_contracts c JOIN owner_authorities issuer ON issuer.id=c.owner_session_id WHERE c.id=$4),
          (SELECT a.domain_verified_at+interval '24 hours' FROM platform_apps a WHERE a.id=$2)
        )) RETURNING expires_at`,
          [
            requestId,
            app.id,
            app.generation,
            contract.id,
            contract.version,
            contract.trust_revision,
            input.redirectUri,
            input.state,
            hash(input.state),
            input.codeChallenge,
            hash(capability),
          ],
        );
        return { contract, expiresAt: stored.expires_at };
      });
      const walletUrl = new URL(`/prove/${requestId}`, origin);
      walletUrl.hash = new URLSearchParams({ request: capability }).toString();
      response.status(201).json({
        requestId,
        walletUrl: walletUrl.toString(),
        expiresAt: row.expiresAt.toISOString(),
      });
    },
  );
  router.get(
    "/proof-requests/:requestId",
    authorize,
    async (request, response) => {
      const requestId = canonicalUuid.parse(request.params.requestId);
      const app = request.platformApp!;
      const [row] = await database.query<{
        id: string;
        status: string;
        expires_at: Date;
        request_active: boolean;
        contract_id: string;
        contract_version: number;
        key_generation: number;
        app_generation: number;
        valid: boolean;
        trusted: boolean;
        contract_valid: boolean;
      }>(
        `SELECT r.id,r.status,r.expires_at,r.expires_at>clock_timestamp() AS request_active,r.contract_id,r.contract_version,r.key_generation,a.key_generation AS app_generation,
      a.disabled_at IS NULL AND a.domain_verified_at>clock_timestamp()-interval '24 hours' AND s.available AS valid,
      EXISTS(SELECT 1 FROM platform_app_trust t WHERE t.app_id=a.id AND t.contract_id=r.contract_id AND t.contract_version=r.contract_version AND t.trust_revision=r.trust_revision) AS trusted,
      v.retired_at IS NULL AND issuer.available AS contract_valid
      FROM platform_requests r JOIN platform_apps a ON a.id=r.app_id JOIN owner_authorities s ON s.id=a.owner_session_id
      JOIN platform_contract_versions v ON v.contract_id=r.contract_id AND v.version=r.contract_version
      JOIN platform_contracts c ON c.id=v.contract_id JOIN owner_authorities issuer ON issuer.id=c.owner_session_id
      WHERE r.id=$1 AND r.app_id=$2`,
        [requestId, app.id],
      );
      requireCondition(
        row,
        404,
        "REQUEST_NOT_FOUND",
        "Proof request not found.",
      );
      requireCondition(
        row.valid &&
          row.trusted &&
          row.contract_valid &&
          row.app_generation === app.generation &&
          row.key_generation === app.generation,
        401,
        "APP_UNAVAILABLE",
        "Application authorization or request trust is no longer current.",
      );
      response.json({
        requestId: row.id,
        status:
          !row.request_active && ["pending", "verified"].includes(row.status)
            ? "expired"
            : row.status,
        expiresAt: row.expires_at.toISOString(),
        contractId: row.contract_id,
        contractVersion: row.contract_version,
      });
    },
  );
  router.post(
    "/proof-requests/:requestId/exchange",
    authorize,
    appWriteLimit,
    async (request, response) => {
      const requestId = canonicalUuid.parse(request.params.requestId);
      const input = exchangeInput.parse(request.body);
      const app = request.platformApp!;
      const [pkceRow] = await database.query<{ code_challenge: string }>(
        "SELECT code_challenge FROM platform_requests WHERE id=$1 AND app_id=$2",
        [requestId, app.id],
      );
      const calculated = Buffer.from(pkceS256(input.codeVerifier));
      const expected = Buffer.from(pkceRow?.code_challenge ?? "");
      requireCondition(
        expected.length === calculated.length &&
          timingSafeEqual(expected, calculated),
        400,
        "EXCHANGE_FAILED",
        "The return code could not be exchanged. Start a new request.",
      );
      const receipt = await database.transaction(async (tx) => {
        const authority = await lockRequestAuthority(
          tx,
          requestId,
          undefined,
          app.generation,
        );
        const row = authority.request;
        const [codeStatus] = await tx.query<{ active: boolean }>(
          "SELECT $1::timestamptz>clock_timestamp() AS active",
          [row.code_expires_at],
        );
        requireCondition(
          authority.head.app_id === app.id &&
            authority.request.status === "verified" &&
            row.verified_at &&
            row.code_expires_at &&
            codeStatus.active &&
            !row.code_consumed_at &&
            row.code_digest &&
            timingSafeEqual(row.code_digest, hash(input.code)),
          400,
          "EXCHANGE_FAILED",
          "The return code could not be exchanged. Start a new request.",
        );
        const key = await signingKey(tx);
        const [clock] = await tx.query<{ iat: number }>(
          "SELECT floor(extract(epoch FROM clock_timestamp()))::int AS iat",
        );
        const jti = randomUUID();
        const claims = {
          iss: origin,
          aud: app.id,
          jti,
          request_id: requestId,
          contract_id: authority.head.contract_id,
          contract_version: authority.head.contract_version,
          contract_digest: authority.contract.digest,
          result: true,
          iat: clock.iat,
          exp: clock.iat + 300,
        };
        const compact = signCompactJws(key.kid, key.privateKey, claims);
        await tx.query(
          `UPDATE platform_requests SET status='exchanged',code_consumed_at=clock_timestamp(),receipt_jti=$2 WHERE id=$1`,
          [requestId, jti],
        );
        return { receipt: compact, claims };
      });
      response.json(receipt);
    },
  );
  return router;
}
