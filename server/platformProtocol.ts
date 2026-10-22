import { createHash } from "node:crypto";
import { type Request, type Response, type NextFunction } from "express";
import { keccak256, toUtf8Bytes } from "ethers";
import { z } from "zod";

export const canonicalUuid = z.uuid().transform((value) => value.toLowerCase());
import type { Database, Queries } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import { semaphoreProofSchema } from "./semaphoreProof.js";

export const hash = (value: string) =>
  createHash("sha256").update(value).digest();
export const protocolNumber = (value: string) =>
  (BigInt(keccak256(toUtf8Bytes(value))) >> 8n).toString();
export const token = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .refine((value) => {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 32 && decoded.toString("base64url") === value;
  });
export const versionInput = z.number().int().min(1).max(2_147_483_647);
export const createInput = z
  .object({
    contractId: canonicalUuid,
    contractVersion: versionInput,
    redirectUri: z.string().max(500),
    state: token,
    codeChallenge: token,
  })
  .strict();
export const capabilityInput = z.object({ capability: token }).strict();
export const challengeInput = z.object({ capability: token }).strict();
export const proveInput = z
  .object({
    capability: token,
    challengeId: canonicalUuid,
    proof: semaphoreProofSchema,
  })
  .strict();
export const returnInput = z.object({ capability: token }).strict();
export const declineInput = z.object({ capability: token }).strict();
export const exchangeInput = z
  .object({ code: token, codeVerifier: token })
  .strict();

export interface AppAuth {
  id: string;
  generation: number;
  origin: string;
}
declare global {
  namespace Express {
    interface Request {
      platformApp?: AppAuth;
    }
  }
}

export function appAuth(database: Database) {
  return async (request: Request, _response: Response, next: NextFunction) => {
    try {
      const authorization = request.get("authorization") ?? "";
      const match = /^Bearer (pk_live_[A-Za-z0-9_-]{43})$/.exec(authorization);
      if (!match)
        throw new HttpError(
          401,
          "APP_KEY_REQUIRED",
          "Application API key is required.",
        );
      const [app] = await database.query<{
        id: string;
        key_digest: Buffer;
        key_generation: number;
        origin: string;
        disabled_at: Date | null;
        owner_available: boolean;
      }>(
        `SELECT a.id,a.key_digest,a.key_generation,a.origin,a.disabled_at,s.expires_at>clock_timestamp() AS owner_available
         FROM platform_apps a JOIN sessions s ON s.id=a.owner_session_id WHERE a.key_digest=$1`,
        [hash(match[1].slice("pk_live_".length))],
      );
      if (!app || app.disabled_at || !app.owner_available)
        throw new HttpError(
          401,
          "APP_KEY_INVALID",
          "Application API key is invalid or unavailable.",
        );
      request.platformApp = {
        id: app.id,
        generation: app.key_generation,
        origin: app.origin,
      };
      next();
    } catch (error) {
      next(error);
    }
  };
}

export async function appCurrent(tx: Queries, app: AppAuth) {
  const [row] = await tx.query<{
    id: string;
    key_generation: number;
    origin: string;
    disabled: boolean;
    owner_available: boolean;
    verified: boolean;
  }>(
    `SELECT a.id,a.key_generation,a.origin,a.disabled_at IS NOT NULL AS disabled,s.expires_at>clock_timestamp() AS owner_available,
      a.domain_verified_at>clock_timestamp()-interval '24 hours' AS verified
     FROM platform_apps a JOIN sessions s ON s.id=a.owner_session_id WHERE a.id=$1 FOR UPDATE OF a`,
    [app.id],
  );
  requireCondition(
    row &&
      row.key_generation === app.generation &&
      !row.disabled &&
      row.owner_available &&
      row.verified,
    401,
    "APP_UNAVAILABLE",
    "Application authorization or domain verification is no longer current.",
  );
  return row;
}

export async function trustedContract(
  tx: Queries,
  appId: string,
  contractId: string,
  version: number,
) {
  const [row] = await tx.query<{
    id: string;
    version: number;
    description: string;
    group_ids: string[];
    digest: string;
    retired_at: Date | null;
    issuer_label: string;
    contract_name: string;
    available: boolean;
    trust_revision: string;
  }>(
    `SELECT v.contract_id AS id,v.version,v.description,v.group_ids,v.digest,v.retired_at,c.issuer_label,c.name AS contract_name,
      s.expires_at>clock_timestamp() AS available,t.trust_revision
     FROM platform_app_trust t JOIN platform_contract_versions v ON v.contract_id=t.contract_id AND v.version=t.contract_version
     JOIN platform_contracts c ON c.id=v.contract_id JOIN sessions s ON s.id=c.owner_session_id
     WHERE t.app_id=$1 AND t.contract_id=$2 AND t.contract_version=$3 FOR UPDATE OF v`,
    [appId, contractId, version],
  );
  requireCondition(
    row && !row.retired_at && row.available,
    403,
    "CONTRACT_NOT_TRUSTED",
    "This contract version is unavailable or not trusted by the application.",
  );
  return row;
}

export async function lockRequestAuthority(
  tx: Queries,
  requestId: string,
  walletSessionId?: string,
  authenticatedGeneration?: number,
) {
  const [head] = await tx.query<{
    app_id: string;
    contract_id: string;
    contract_version: number;
    trust_revision: string;
  }>(
    "SELECT app_id,contract_id,contract_version,trust_revision FROM platform_requests WHERE id=$1",
    [requestId],
  );
  requireCondition(
    head,
    404,
    "REQUEST_UNAVAILABLE",
    "This request is unavailable.",
  );
  const [app] = await tx.query<{
    id: string;
    key_generation: number;
    disabled: boolean;
    domain_valid: boolean;
    app_owner_valid: boolean;
    origin: string;
  }>(
    `SELECT a.id,a.key_generation,a.disabled_at IS NOT NULL AS disabled,
     a.domain_verified_at>clock_timestamp()-interval '24 hours' AS domain_valid,s.expires_at>clock_timestamp() AS app_owner_valid,a.origin
     FROM platform_apps a JOIN sessions s ON s.id=a.owner_session_id WHERE a.id=$1 FOR UPDATE OF a`,
    [head.app_id],
  );
  requireCondition(
    app &&
      !app.disabled &&
      app.domain_valid &&
      app.app_owner_valid &&
      (authenticatedGeneration === undefined ||
        app.key_generation === authenticatedGeneration),
    401,
    "APP_UNAVAILABLE",
    "Application authorization or domain verification is no longer current.",
  );
  const [contract] = await tx.query<{
    retired: boolean;
    issuer_valid: boolean;
    digest: string;
    group_ids: string[];
    description: string;
    contract_name: string;
    issuer_label: string;
  }>(
    `SELECT v.retired_at IS NOT NULL AS retired,s.expires_at>clock_timestamp() AS issuer_valid,v.digest,v.group_ids,v.description,c.name AS contract_name,c.issuer_label
     FROM platform_contract_versions v JOIN platform_contracts c ON c.id=v.contract_id JOIN sessions s ON s.id=c.owner_session_id
     WHERE v.contract_id=$1 AND v.version=$2 FOR UPDATE OF v`,
    [head.contract_id, head.contract_version],
  );
  requireCondition(
    contract && !contract.retired && contract.issuer_valid,
    403,
    "CONTRACT_UNAVAILABLE",
    "The trusted contract is no longer available.",
  );
  const [request] = await tx.query<{
    status: string;
    key_generation: number;
    expires_at: Date;
    request_active: boolean;
    redirect_uri: string;
    state: string;
    state_digest: Buffer;
    code_challenge: string;
    code_digest: Buffer | null;
    code_expires_at: Date | null;
    code_consumed_at: Date | null;
    wallet_session_id: string | null;
    verified_at: Date | null;
    code_generation: number;
    trust_revision: string;
  }>(
    `SELECT r.status,r.key_generation,r.expires_at,r.redirect_uri,r.state,r.state_digest,r.code_challenge,r.code_digest,r.code_expires_at,r.code_consumed_at,r.trust_revision,
     r.expires_at>clock_timestamp() AS request_active,r.wallet_session_id,r.verified_at,a.key_generation AS code_generation FROM platform_requests r JOIN platform_apps a ON a.id=r.app_id
     WHERE r.id=$1 AND r.app_id=$2 FOR UPDATE OF r`,
    [requestId, head.app_id],
  );
  requireCondition(
    request &&
      request.key_generation === app.key_generation &&
      request.code_generation === app.key_generation &&
      request.request_active,
    403,
    "REQUEST_UNAVAILABLE",
    "This request has expired or changed.",
  );
  const [pin] = await tx.query(
    "SELECT 1 FROM platform_app_trust WHERE app_id=$1 AND contract_id=$2 AND contract_version=$3 AND trust_revision=$4",
    [
      head.app_id,
      head.contract_id,
      head.contract_version,
      request.trust_revision,
    ],
  );
  requireCondition(
    pin,
    403,
    "CONTRACT_NOT_TRUSTED",
    "The application no longer trusts this contract version.",
  );
  const [authorityCurrent] = await tx.query<{ current: boolean }>(
    `SELECT a.disabled_at IS NULL
       AND a.key_generation=$2
       AND a.domain_verified_at>clock_timestamp()-interval '24 hours'
       AND app_owner.expires_at>clock_timestamp()
       AND issuer.expires_at>clock_timestamp()
       AND v.retired_at IS NULL
       AND r.expires_at>clock_timestamp()
       AND EXISTS (SELECT 1 FROM platform_app_trust t WHERE t.app_id=r.app_id AND t.contract_id=r.contract_id AND t.contract_version=r.contract_version AND t.trust_revision=r.trust_revision) AS current
     FROM platform_requests r
     JOIN platform_apps a ON a.id=r.app_id
     JOIN sessions app_owner ON app_owner.id=a.owner_session_id
     JOIN platform_contract_versions v ON v.contract_id=r.contract_id AND v.version=r.contract_version
     JOIN platform_contracts c ON c.id=v.contract_id
     JOIN sessions issuer ON issuer.id=c.owner_session_id
     WHERE r.id=$1 AND r.app_id=$3`,
    [requestId, app.key_generation, head.app_id],
  );
  requireCondition(
    authorityCurrent?.current,
    403,
    "REQUEST_UNAVAILABLE",
    "The request authority expired or changed while it was being processed.",
  );
  if (walletSessionId)
    requireCondition(
      request.wallet_session_id === walletSessionId ||
        request.status === "pending",
      403,
      "REQUEST_UNAVAILABLE",
      "This request belongs to another wallet session.",
    );
  return { head, app, contract, request };
}
