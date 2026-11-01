import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  Router,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import { Group } from "@semaphore-protocol/group";
import type { SemaphoreProof } from "@semaphore-protocol/proof";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import { semaphoreProofSchema, verifySemaphoreProofBounded } from "./semaphoreProof.js";
import { customProofSchema, verifyGroth16Bounded } from "./groth16Verifier.js";
import { BN254_SCALAR_FIELD, GROTH16_ADAPTER, type Groth16AdapterConfig } from "../shared/platform.js";
import type { Database } from "./database.js";
import { HttpError, requireCondition } from "./errors.js";
import {
  capabilityInput,
  canonicalUuid,
  challengeInput,
  declineInput,
  hash,
  lockRequestAuthority,
  protocolNumber,
  proveInput,
  returnInput,
} from "./platformProtocol.js";

export function platformWalletRoutes(
  database: Database,
  sessionOptions: {
    origin: string;
    secure: boolean;
    checkOrigin(req: Request, res: Response, next: NextFunction): void;
    checkCsrf(req: Request, res: Response, next: NextFunction): void;
  },
) {
  const router = Router();
  router.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });
  router.use(
    rateLimit({
      windowMs: 60_000,
      limit: 120,
      keyGenerator: (request) =>
        request.session?.id ?? ipKeyGenerator(request.ip ?? "127.0.0.1"),
      standardHeaders: "draft-8",
      legacyHeaders: false,
    }),
  );
  router.use((request, response, next) =>
    sessionOptions.checkOrigin(request, response, next),
  );
  router.use((request, response, next) =>
    sessionOptions.checkCsrf(request, response, next),
  );
  const requireSession = (request: Request) => {
    requireCondition(
      request.session,
      401,
      "SESSION_REQUIRED",
      "Start a Portkey session first.",
    );
    return request.session!;
  };
  router.post(
    "/proof-requests/:requestId/lookup",
    async (request, response) => {
      const wallet = requireSession(request);
      const requestId = canonicalUuid.parse(request.params.requestId);
      const { capability } = capabilityInput.parse(request.body);
      const [row] = await database.query<{
        id: string;
        app_id: string;
        name: string;
        origin: string;
        redirect_uri: string;
        contract_id: string;
        contract_version: number;
        contract_name: string;
        issuer_label: string;
        description: string;
        digest: string;
        group_ids: string[];
        adapter: string;
        proof_depth: number | null;
        adapter_config: Groth16AdapterConfig | null;
        expires_at: Date;
        request_active: boolean;
        available: boolean;
        retired: boolean;
        status: string;
        wallet_session_id: string | null;
        key_generation: number;
        domain_valid: boolean;
        app_owner_valid: boolean;
        trusted: boolean;
      }>(
        `SELECT r.id,r.app_id,a.name,a.origin,r.redirect_uri,r.contract_id,r.contract_version,c.name AS contract_name,c.issuer_label,v.description,v.digest,v.group_ids,v.adapter,v.proof_depth,v.adapter_config,r.expires_at,
       r.expires_at>clock_timestamp() AS request_active,s.available AS available,v.retired_at IS NOT NULL AS retired,r.status,r.wallet_session_id,r.key_generation,
       a.key_generation=r.key_generation AND a.disabled_at IS NULL AND a.domain_verified_at>clock_timestamp()-interval '24 hours' AS domain_valid,
       appOwner.available AS app_owner_valid,
       EXISTS(SELECT 1 FROM platform_app_trust t WHERE t.app_id=a.id AND t.contract_id=r.contract_id AND t.contract_version=r.contract_version AND t.trust_revision=r.trust_revision) AS trusted
       FROM platform_requests r JOIN platform_apps a ON a.id=r.app_id JOIN owner_authorities appOwner ON appOwner.id=a.owner_session_id
       JOIN platform_contract_versions v ON v.contract_id=r.contract_id AND v.version=r.contract_version JOIN platform_contracts c ON c.id=v.contract_id JOIN owner_authorities s ON s.id=c.owner_session_id
       WHERE r.id=$1 AND r.capability_digest=$2`,
        [requestId, hash(capability)],
      );
      requireCondition(
        row &&
          row.request_active &&
          row.available &&
          row.app_owner_valid &&
          row.trusted &&
          !row.retired &&
          row.domain_valid &&
          (row.status === "pending" ||
            (row.status === "verified" && row.wallet_session_id === wallet.id)),
        403,
        "REQUEST_UNAVAILABLE",
        "This request is unavailable or expired.",
      );
      const groups = await database.query<{ id: string; name: string }>(
        "SELECT id,name FROM credential_groups WHERE id=ANY($1::uuid[]) ORDER BY id",
        [row.group_ids],
      );
      response.json({
        requestId: row.id,
        status: row.status,
        app: {
          name: row.name,
          origin: row.origin,
          redirectUri: row.redirect_uri,
        },
        contract: {
          id: row.contract_id,
          version: row.contract_version,
          name: row.contract_name,
          issuerLabel: row.issuer_label,
          description: row.description,
          digest: row.digest,
          groups,
          adapter: row.adapter,
          proofDepth: row.proof_depth,
          adapterConfig: row.adapter_config,
        },
        expiresAt: row.expires_at.toISOString(),
      });
    },
  );
  router.post(
    "/proof-requests/:requestId/challenge",
    async (request, response) => {
      const wallet = requireSession(request);
      const requestId = canonicalUuid.parse(request.params.requestId);
      const { capability } = challengeInput.parse(request.body);
      const challenge = await database.transaction(async (tx) => {
        const authority = await lockRequestAuthority(tx, requestId);
        const { head, app, contract, request: row } = authority;
        requireCondition(
          row.status === "pending",
          409,
          "REQUEST_UNAVAILABLE",
          "This request is unavailable or expired.",
        );
        const [cap] = await tx.query<{ valid: boolean }>(
          "SELECT capability_digest=$2 AS valid FROM platform_requests WHERE id=$1",
          [requestId, hash(capability)],
        );
        requireCondition(
          cap?.valid,
          403,
          "REQUEST_UNAVAILABLE",
          "This request is unavailable or expired.",
        );
        if (contract.adapter === GROTH16_ADAPTER) {
          requireCondition(
            contract.adapter_config,
            422,
            "INVALID_VERIFICATION_KEY",
            "The pinned verification key is unavailable.",
          );
          const [existingChallenge] = await tx.query<{ id: string }>(
            "SELECT id FROM platform_challenges WHERE request_id=$1 FOR UPDATE",
            [requestId],
          );
          const challengeId = existingChallenge?.id ?? randomUUID();
          const nonce = randomBytes(32).toString("hex");
          const challengeHash = createHash("sha256")
            .update(
              [
                "portkey:custom-proof-challenge:v1",
                requestId,
                wallet.id,
                head.app_id,
                row.redirect_uri,
                contract.digest,
                nonce,
              ].join(":"),
            )
            .digest("hex");
          const scalar =
            (BigInt(`0x${challengeHash}`) % (BN254_SCALAR_FIELD - 1n) + 1n).toString();
          const [walletRow] = await tx.query<{
            expires_at: Date;
            active: boolean;
          }>(
            "SELECT expires_at,expires_at>clock_timestamp() AS active FROM sessions WHERE id=$1",
            [wallet.id],
          );
          requireCondition(walletRow?.active, 401, "SESSION_EXPIRED", "Start a new Portkey session.");
          const [expiry] = await tx.query<{ value: Date }>(
            "SELECT LEAST(clock_timestamp()+interval '2 minutes',$1::timestamptz,$2::timestamptz) AS value",
            [row.expires_at, walletRow.expires_at],
          );
          const [stored] = await tx.query<{ expires_at: Date }>(
            `INSERT INTO platform_challenges(id,request_id,wallet_session_id,accepted_root,scope,message,policy_digest,expires_at)
             VALUES($1,$2,$3,$4,'',$4,$5,$6)
             ON CONFLICT(request_id) DO UPDATE SET id=EXCLUDED.id,
               wallet_session_id=EXCLUDED.wallet_session_id,
               accepted_root=EXCLUDED.accepted_root,scope='',message=EXCLUDED.message,
               policy_digest=EXCLUDED.policy_digest,expires_at=EXCLUDED.expires_at,
               consumed_at=NULL,staged_public_signals=NULL,staged_nullifier_digest=NULL
             RETURNING expires_at`,
            [challengeId, requestId, wallet.id, scalar, contract.digest, expiry.value],
          );
          return {
            adapter: GROTH16_ADAPTER,
            challengeId,
            challenge: scalar,
            adapterFingerprint: contract.adapter_config.fingerprint,
            expiresAt: stored.expires_at.toISOString(),
          };
        }
        const groups = await tx.query<{ commitment: string }>(
          `SELECT DISTINCT m.commitment FROM credential_group_commitments m JOIN credential_groups g ON g.id=m.group_id JOIN owner_authorities s ON s.id=g.owner_session_id
        WHERE m.group_id=ANY($1::uuid[]) AND s.available ORDER BY m.commitment LIMIT 1001`,
          [contract.group_ids],
        );
        requireCondition(
          groups.length <= 1000,
          409,
          "PROOF_GROUP_LIMIT",
          "The trusted contract exceeds the proof size limit.",
        );
        const commitments = groups.map((item) => BigInt(item.commitment));
        const group = new Group(commitments);
        const previous = await tx.query<{ id: string }>(
          "SELECT id FROM platform_challenges WHERE request_id=$1 FOR UPDATE",
          [requestId],
        );
        const challengeId = previous[0]?.id ?? randomUUID();
        const nonce = randomBytes(32).toString("base64url");
        const scope = protocolNumber(
          `portkey:application-eligibility-scope:v1:${requestId}`,
        );
        const [walletRow] = await tx.query<{
          expires_at: Date;
          active: boolean;
        }>(
          "SELECT expires_at,expires_at>clock_timestamp() AS active FROM sessions WHERE id=$1",
          [wallet.id],
        );
        requireCondition(
          walletRow?.active,
          401,
          "SESSION_EXPIRED",
          "Start a new Portkey session.",
        );
        const [expiry] = await tx.query<{ value: Date }>(
          "SELECT LEAST(clock_timestamp()+interval '2 minutes',$1::timestamptz,$2::timestamptz) AS value",
          [row.expires_at, walletRow.expires_at],
        );
        const message = protocolNumber(
          [
            "portkey:application-proof:v1",
            challengeId,
            nonce,
            requestId,
            head.app_id,
            app.key_generation,
            head.contract_id,
            head.contract_version,
            contract.digest,
            row.redirect_uri,
            row.state_digest.toString("hex"),
            row.code_challenge,
            row.trust_revision,
            wallet.id,
            group.root.toString(),
            expiry.value.toISOString(),
            "semaphore-membership-v1",
            "semaphore-v4",
            10,
          ].join(":"),
        );
        const [stored] = await tx.query<{ expires_at: Date }>(
          `INSERT INTO platform_challenges(id,request_id,wallet_session_id,accepted_root,scope,message,policy_digest,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT(request_id) DO UPDATE SET id=EXCLUDED.id,wallet_session_id=EXCLUDED.wallet_session_id,accepted_root=EXCLUDED.accepted_root,scope=EXCLUDED.scope,message=EXCLUDED.message,
        policy_digest=EXCLUDED.policy_digest,expires_at=EXCLUDED.expires_at,consumed_at=NULL RETURNING expires_at`,
          [
            challengeId,
            requestId,
            wallet.id,
            group.root.toString(),
            scope,
            message,
            contract.digest,
            expiry.value,
          ],
        );
        return {
          challengeId,
          version: "semaphore-v4",
          depth: 10,
          root: group.root.toString(),
          scope,
          message,
          commitments: commitments.map(String),
          expiresAt: stored.expires_at.toISOString(),
        };
      });
      response.json(challenge);
    },
  );
  router.post("/proof-requests/:requestId/prove", async (request, response) => {
    const wallet = requireSession(request);
    const requestId = canonicalUuid.parse(request.params.requestId);
    const input = proveInput.parse(request.body);
    const [challenge] = await database.query<{
      request_id: string;
      wallet_session_id: string;
      accepted_root: string;
      scope: string;
      message: string;
      expires_at: Date;
      active: boolean;
      consumed_at: Date | null;
      status: string;
      request_wallet_session_id: string | null;
      policy_digest: string;
      adapter: string;
      adapter_config: Groth16AdapterConfig | null;
    }>(
      `SELECT c.request_id,c.wallet_session_id,c.accepted_root,c.scope,c.message,c.expires_at,c.expires_at>clock_timestamp() AS active,c.consumed_at,r.status,r.wallet_session_id AS request_wallet_session_id,c.policy_digest,v.adapter,v.adapter_config FROM platform_challenges c JOIN platform_requests r ON r.id=c.request_id JOIN platform_contract_versions v ON v.contract_id=r.contract_id AND v.version=r.contract_version
      WHERE c.id=$1 AND c.request_id=$2 AND r.capability_digest=$3`,
      [input.challengeId, requestId, hash(input.capability)],
    );
    requireCondition(
      challenge &&
        challenge.wallet_session_id === wallet.id &&
        (challenge.active ||
          (challenge.status === "verified" &&
            challenge.request_wallet_session_id === wallet.id &&
            challenge.consumed_at)),
      403,
      "PROOF_INVALID",
      "This proof is invalid or expired. Refresh and try again.",
    );
    if (challenge.adapter === GROTH16_ADAPTER) {
      const config = challenge.adapter_config;
      requireCondition(
        config &&
          challenge.active &&
          !challenge.consumed_at &&
          challenge.status === "pending",
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      const parsed = customProofSchema.parse(input.proof);
      requireCondition(
        parsed.publicSignals.length === config.nPublic &&
          parsed.proof.curve === "bn128" &&
          parsed.publicSignals[0] === challenge.message &&
          parsed.publicSignals[1] === "1" &&
          parsed.publicSignals[2] !== "0",
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      const valid = await verifyGroth16Bounded(config, parsed);
      requireCondition(
        valid,
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      await database.transaction(async (tx) => {
        const authority = await lockRequestAuthority(tx, requestId, wallet.id);
        const [cap] = await tx.query<{ valid: boolean }>(
          "SELECT capability_digest=$2 AS valid FROM platform_requests WHERE id=$1",
          [requestId, hash(input.capability)],
        );
        requireCondition(
          cap?.valid &&
            authority.contract.adapter === GROTH16_ADAPTER &&
            authority.contract.digest === challenge.policy_digest &&
            authority.contract.adapter_config?.fingerprint === config.fingerprint,
          403,
          "PROOF_INVALID",
          "This proof is invalid or expired. Refresh and try again.",
        );
        const [stored] = await tx.query<{
          active: boolean;
          consumed_at: Date | null;
          message: string;
        }>(
          "SELECT expires_at>clock_timestamp() AS active,consumed_at,message FROM platform_challenges WHERE id=$1 AND request_id=$2 AND wallet_session_id=$3 FOR UPDATE",
          [input.challengeId, requestId, wallet.id],
        );
        requireCondition(
          stored?.active &&
            !stored.consumed_at &&
            stored.message === parsed.publicSignals[0] &&
            authority.request.status === "pending" &&
            (!authority.request.wallet_session_id ||
              authority.request.wallet_session_id === wallet.id),
          403,
          "PROOF_INVALID",
          "This proof is invalid or expired. Refresh and try again.",
        );
        const nullifierDigest = createHash("sha256")
          .update(
            `${GROTH16_ADAPTER}:${authority.head.contract_id}:${authority.head.contract_version}:${parsed.publicSignals[2]}`,
          )
          .digest("hex");
        await tx.query(
          "UPDATE platform_challenges SET consumed_at=clock_timestamp(),staged_public_signals=$2::jsonb,staged_nullifier_digest=$3 WHERE id=$1",
          [input.challengeId, JSON.stringify(parsed.publicSignals), nullifierDigest],
        );
      });
      response.json({
        verified: true,
        approved: false,
        disclosedSignals: config.publicSignalNames.map((name, index) => ({
          name,
          value: parsed.publicSignals[index],
        })),
      });
      return;
    }
    const proof = semaphoreProofSchema.parse(input.proof) as SemaphoreProof;
    requireCondition(
      proof.merkleTreeDepth === 10 &&
        proof.merkleTreeRoot === challenge.accepted_root &&
        proof.scope === challenge.scope &&
        proof.message === challenge.message,
      403,
      "PROOF_INVALID",
      "This proof is invalid or expired. Refresh and try again.",
    );
    let valid = false;
    try {
      valid = await verifySemaphoreProofBounded(proof);
    } catch (error) {
      if (error instanceof HttpError && error.status === 429) throw error;
    }
    requireCondition(
      valid,
      403,
      "PROOF_INVALID",
      "This proof is invalid or expired. Refresh and try again.",
    );
    const alreadyVerified = await database.transaction(async (tx) => {
      const authority = await lockRequestAuthority(tx, requestId);
      const { request: current, contract } = authority;
      const [cap] = await tx.query<{ valid: boolean }>(
        "SELECT capability_digest=$2 AS valid FROM platform_requests WHERE id=$1",
        [requestId, hash(input.capability)],
      );
      requireCondition(
        cap?.valid,
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      requireCondition(
        contract.digest === challenge.policy_digest,
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      const [stored] = await tx.query<{
        accepted_root: string;
        scope: string;
        message: string;
        active: boolean;
        consumed_at: Date | null;
      }>(
        "SELECT accepted_root,scope,message,expires_at>clock_timestamp() AS active,consumed_at FROM platform_challenges WHERE id=$1 AND request_id=$2 AND wallet_session_id=$3 FOR UPDATE",
        [input.challengeId, requestId, wallet.id],
      );
      requireCondition(
        stored &&
          (stored.active ||
            (current.status === "verified" &&
              current.wallet_session_id === wallet.id &&
              stored.consumed_at)) &&
          stored.accepted_root === proof.merkleTreeRoot &&
          stored.scope === proof.scope &&
          stored.message === proof.message,
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      if (
        current.status === "verified" &&
        current.wallet_session_id === wallet.id &&
        stored.consumed_at
      ) {
        const [existing] = await tx.query<{ nullifier: string }>(
          "SELECT nullifier FROM platform_nullifiers WHERE request_id=$1",
          [requestId],
        );
        requireCondition(
          existing?.nullifier === proof.nullifier,
          403,
          "PROOF_INVALID",
          "This proof is invalid or expired. Refresh and try again.",
        );
        return true;
      }
      requireCondition(
        current.status === "pending" &&
          !stored.consumed_at &&
          (!current.wallet_session_id ||
            current.wallet_session_id === wallet.id),
        403,
        "PROOF_INVALID",
        "This proof is invalid or expired. Refresh and try again.",
      );
      await tx.query(
        "INSERT INTO platform_nullifiers(request_id,nullifier) VALUES($1,$2)",
        [requestId, proof.nullifier],
      );
      await tx.query(
        `UPDATE platform_challenges SET consumed_at=clock_timestamp() WHERE id=$1`,
        [input.challengeId],
      );
      await tx.query(
        `UPDATE platform_requests SET status='verified',verified_at=clock_timestamp(),wallet_session_id=$2 WHERE id=$1`,
        [requestId, wallet.id],
      );
      return false;
    });
    response.json({ verified: true, alreadyVerified });
  });
  router.post(
    "/proof-requests/:requestId/approve-custom-proof",
    async (request, response) => {
      const wallet = requireSession(request);
      const requestId = canonicalUuid.parse(request.params.requestId);
      const { capability } = challengeInput.parse(request.body);
      const alreadyApproved = await database.transaction(async (tx) => {
        const authority = await lockRequestAuthority(tx, requestId, wallet.id);
        const [cap] = await tx.query<{ valid: boolean }>(
          "SELECT capability_digest=$2 AS valid FROM platform_requests WHERE id=$1",
          [requestId, hash(capability)],
        );
        requireCondition(
          cap?.valid,
          403,
          "PROOF_INVALID",
          "This proof cannot be approved. Start again from the application.",
        );
        const confirmation = async (contractId: string, version: number) => {
          const [row] = await tx.query<{
            disclosed: boolean;
            nullifier_matches: boolean;
          }>(
            "SELECT c.staged_public_signals IS NOT NULL AS disclosed,c.staged_nullifier_digest=n.nullifier_digest AS nullifier_matches FROM platform_challenges c JOIN platform_custom_nullifiers n ON n.request_id=c.request_id WHERE c.request_id=$1 AND c.wallet_session_id=$2 AND n.contract_id=$3 AND n.contract_version=$4",
            [requestId, wallet.id, contractId, version],
          );
          return Boolean(row?.disclosed && row.nullifier_matches);
        };
        requireCondition(
          authority.contract.adapter === GROTH16_ADAPTER,
          403,
          "PROOF_INVALID",
          "This request uses a different proof adapter.",
        );
        if (
          authority.request.status === "verified" &&
          authority.request.wallet_session_id === wallet.id
        ) {
          requireCondition(
            await confirmation(
              authority.head.contract_id,
              authority.head.contract_version,
            ),
            403,
            "PROOF_INVALID",
            "This request was not approved with the imported proof.",
          );
          return true;
        }
        requireCondition(
          authority.request.status === "pending",
          403,
          "PROOF_INVALID",
          "This proof cannot be approved. Start again from the application.",
        );
        const [stored] = await tx.query<{
          staged_public_signals: string[] | null;
          staged_nullifier_digest: string | null;
          consumed_at: Date | null;
          active: boolean;
        }>(
          "SELECT staged_public_signals,staged_nullifier_digest,consumed_at,expires_at>clock_timestamp() AS active FROM platform_challenges WHERE request_id=$1 AND wallet_session_id=$2 FOR UPDATE",
          [requestId, wallet.id],
        );
        requireCondition(
          stored?.active &&
            stored.consumed_at &&
            stored.staged_public_signals &&
            stored.staged_nullifier_digest,
          403,
          "PROOF_INVALID",
          "Import and verify a fresh proof before approving it.",
        );
        const [spent] = await tx.query<{ request_id: string }>(
          "INSERT INTO platform_custom_nullifiers(contract_id,contract_version,nullifier_digest,request_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING request_id",
          [
            authority.head.contract_id,
            authority.head.contract_version,
            stored.staged_nullifier_digest,
            requestId,
          ],
        );
        requireCondition(
          spent,
          403,
          "PROOF_INVALID",
          "This nullifier has already been used for this contract version.",
        );
        await tx.query(
          "UPDATE platform_requests SET status='verified',verified_at=clock_timestamp(),wallet_session_id=$2 WHERE id=$1",
          [requestId, wallet.id],
        );
        return false;
      });
      response.json({ approved: true, alreadyApproved });
    },
  );
  router.post(
    "/proof-requests/:requestId/return",
    async (request, response) => {
      const wallet = requireSession(request);
      const requestId = canonicalUuid.parse(request.params.requestId);
      const { capability } = returnInput.parse(request.body);
      const code = randomBytes(32).toString("base64url");
      const result = await database.transaction(async (tx) => {
        const authority = await lockRequestAuthority(tx, requestId, wallet.id);
        const [cap] = await tx.query<{ valid: boolean }>(
          "SELECT capability_digest=$2 AS valid FROM platform_requests WHERE id=$1",
          [requestId, hash(capability)],
        );
        requireCondition(
          cap?.valid &&
            authority.request.status === "verified" &&
            authority.request.wallet_session_id === wallet.id &&
            !authority.request.code_consumed_at,
          403,
          "RETURN_UNAVAILABLE",
          "This verified request cannot be returned.",
        );
        const [stored] = await tx.query<{ code_expires_at: Date }>(
          `UPDATE platform_requests SET code_digest=$2,
        code_expires_at=LEAST(clock_timestamp()+interval '60 seconds',expires_at) WHERE id=$1 RETURNING code_expires_at`,
          [requestId, hash(code)],
        );
        return {
          redirectUri: authority.request.redirect_uri,
          state: authority.request.state,
          expiresAt: stored.code_expires_at,
        };
      });
      const callback = new URL(result.redirectUri);
      callback.hash = new URLSearchParams({
        code,
        state: result.state ?? "",
      }).toString();
      response.json({
        redirectUrl: callback.toString(),
        expiresAt: result.expiresAt.toISOString(),
      });
    },
  );
  router.post(
    "/proof-requests/:requestId/decline",
    async (request, response) => {
      const wallet = requireSession(request);
      const requestId = canonicalUuid.parse(request.params.requestId);
      const { capability } = declineInput.parse(request.body);
      const [row] = await database.transaction(async (tx) => {
        const authority = await lockRequestAuthority(tx, requestId, wallet.id);
        const [cap] = await tx.query<{ valid: boolean }>(
          "SELECT capability_digest=$2 AS valid FROM platform_requests WHERE id=$1",
          [requestId, hash(capability)],
        );
        requireCondition(
          cap?.valid && authority.request.status === "pending",
          403,
          "REQUEST_UNAVAILABLE",
          "This request cannot be declined.",
        );
        await tx.query(
          `UPDATE platform_requests SET status='declined',wallet_session_id=$2,code_digest=NULL WHERE id=$1`,
          [requestId, wallet.id],
        );
        return [authority.request];
      });
      const callback = new URL(row.redirect_uri);
      callback.hash = new URLSearchParams({
        error: "access_denied",
        state: row.state,
      }).toString();
      response.json({ redirectUrl: callback.toString() });
    },
  );
  return router;
}
