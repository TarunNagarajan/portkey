import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
} from "node:crypto";

const canonical = (value: string, maximum = 8192) => {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > maximum) return null;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? bytes : null;
};
const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const digest = /^[a-f0-9]{64}$/;

export interface PortkeyClientConfig {
  origin: string;
  apiKey: string;
  appId: string;
}
export interface ProofRequestInput {
  contractId: string;
  contractVersion: number;
  redirectUri: string;
}
export interface ProofRequestResult {
  requestId: string;
  walletUrl: string;
  expiresAt: string;
  state: string;
  codeVerifier: string;
}
export interface ReceiptClaims {
  iss: string;
  aud: string;
  jti: string;
  request_id: string;
  contract_id: string;
  contract_version: number;
  contract_digest: string;
  result: true;
  iat: number;
  exp: number;
}
export interface ReceiptExpectation {
  issuer: string;
  audience: string;
  requestId: string;
  contractId: string;
  contractVersion: number;
  contractDigest: string;
  now?: number;
}

function normalizeOrigin(value: string) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" &&
    !(
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    )
  )
    throw new Error("Portkey origin must use HTTPS.");
  if (
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.origin !== value
  )
    throw new Error("Portkey origin must be an exact origin.");
  return url.origin;
}

async function apiJson<T>(
  url: string,
  apiKey: string,
  body: unknown,
): Promise<T> {
  const { response, value } = await boundedJson<{
    error?: { message?: string };
  }>(
    url,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      cache: "no-store",
      redirect: "error",
    },
    16_384,
  );
  if (!response.ok)
    throw new Error(
      value?.error?.message ?? "Portkey could not complete the request.",
    );
  return value as T;
}

async function boundedJson<T>(
  url: string,
  init: RequestInit,
  maximumBytes: number,
) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    const declaredLength = Number(response.headers.get("content-length") ?? 0);
    if (declaredLength > maximumBytes) {
      controller.abort();
      await response.body?.cancel().catch(() => undefined);
      throw new Error("Portkey response is too large.");
    }
    if (!response.body) throw new Error("Portkey response is empty.");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maximumBytes) {
          controller.abort();
          await reader.cancel().catch(() => undefined);
          throw new Error("Portkey response is too large.");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    let value: T | null = null;
    try {
      value = JSON.parse(new TextDecoder().decode(bytes)) as T;
    } catch {
      /* The caller reports an invalid response. */
    }
    return { response, value };
  } finally {
    clearTimeout(timeout);
    if (!controller.signal.aborted) controller.abort();
  }
}

export function createPKCE() {
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(verifier, "ascii")
    .digest("base64url");
  return { verifier, state, codeChallenge };
}

export function createPortkeyClient(config: PortkeyClientConfig) {
  const origin = normalizeOrigin(config.origin);
  if (
    !/^pk_live_[A-Za-z0-9_-]{43}$/.test(config.apiKey) ||
    !uuid.test(config.appId)
  )
    throw new Error("Portkey application credentials are invalid.");

  async function createProofRequest(
    input: ProofRequestInput,
  ): Promise<ProofRequestResult> {
    if (
      !uuid.test(input.contractId) ||
      !Number.isSafeInteger(input.contractVersion) ||
      input.contractVersion < 1
    )
      throw new Error("Contract version is invalid.");
    const flow = createPKCE();
    const result = await apiJson<{
      requestId: string;
      walletUrl: string;
      expiresAt: string;
    }>(`${origin}/v1/proof-requests`, config.apiKey, {
      contractId: input.contractId,
      contractVersion: input.contractVersion,
      redirectUri: input.redirectUri,
      state: flow.state,
      codeChallenge: flow.codeChallenge,
    });
    const wallet = new URL(result.walletUrl);
    if (
      wallet.origin !== origin ||
      !wallet.pathname.startsWith("/prove/") ||
      !wallet.hash
    )
      throw new Error("Portkey returned an invalid wallet address.");
    return { ...result, state: flow.state, codeVerifier: flow.verifier };
  }

  async function exchange(
    requestId: string,
    code: string,
    codeVerifier: string,
    expected: Omit<ReceiptExpectation, "issuer" | "audience" | "requestId">,
  ) {
    if (!uuid.test(requestId)) throw new Error("Proof request ID is invalid.");
    const result = await apiJson<{ receipt: string; claims: ReceiptClaims }>(
      `${origin}/v1/proof-requests/${requestId}/exchange`,
      config.apiKey,
      { code, codeVerifier },
    );
    const claims = await verifyReceipt(result.receipt, {
      ...expected,
      issuer: origin,
      audience: config.appId,
      requestId,
    });
    if (JSON.stringify(claims) !== JSON.stringify(result.claims))
      throw new Error("Portkey returned inconsistent receipt data.");
    return { receipt: result.receipt, claims };
  }

  return {
    origin,
    appId: config.appId,
    createProofRequest,
    exchange,
    verifyReceipt: (
      receipt: string,
      expected: Omit<ReceiptExpectation, "issuer" | "audience">,
    ) =>
      verifyReceipt(receipt, {
        ...expected,
        issuer: origin,
        audience: config.appId,
      }),
  };
}

const jwksCache = new Map<string, { expires: number; keys: unknown[] }>();
const jwksInflight = new Map<string, Promise<unknown[]>>();
const lastForcedJwksRefresh = new Map<string, number>();
const forcedJwksRefreshInterval = 1_000;

async function fetchJwks(origin: string) {
  const current = jwksInflight.get(origin);
  if (current) return current;
  const pending = (async () => {
    const { response, value } = await boundedJson<{ keys?: unknown }>(
      `${origin}/v1/.well-known/jwks.json`,
      { cache: "no-store", redirect: "error" },
      8_192,
    );
    if (!response.ok) throw new Error("Portkey signing keys are unavailable.");
    if (!value || !Array.isArray(value.keys) || value.keys.length > 8)
      throw new Error("Portkey signing keys are invalid.");
    jwksCache.set(origin, { expires: Date.now() + 60_000, keys: value.keys });
    return value.keys;
  })();
  jwksInflight.set(origin, pending);
  try {
    return await pending;
  } finally {
    if (jwksInflight.get(origin) === pending) jwksInflight.delete(origin);
  }
}

async function pinnedJwks(origin: string, refresh = false) {
  const cached = jwksCache.get(origin);
  if (!refresh && cached && cached.expires > Date.now()) return cached.keys;
  if (refresh) {
    const pending = jwksInflight.get(origin);
    if (pending) return pending;
    const now = Date.now();
    const last = lastForcedJwksRefresh.get(origin);
    if (last !== undefined && now - last < forcedJwksRefreshInterval) {
      if (cached) return cached.keys;
      throw new Error("Portkey signing keys are unavailable.");
    }
    lastForcedJwksRefresh.set(origin, now);
  }
  return fetchJwks(origin);
}

export async function verifyReceipt(
  receipt: string,
  expected: ReceiptExpectation,
): Promise<ReceiptClaims> {
  if (
    !uuid.test(expected.audience) ||
    !uuid.test(expected.requestId) ||
    !uuid.test(expected.contractId) ||
    !Number.isSafeInteger(expected.contractVersion) ||
    expected.contractVersion < 1 ||
    !digest.test(expected.contractDigest) ||
    (expected.now !== undefined && !Number.isSafeInteger(expected.now))
  )
    throw new Error("Verification expectations are invalid.");
  const origin = normalizeOrigin(expected.issuer);
  if (receipt.length > 12_000)
    throw new Error("Verification receipt is too large.");
  const parts = receipt.split(".");
  if (parts.length !== 3) throw new Error("Verification receipt is invalid.");
  const headerBytes = canonical(parts[0], 1024);
  const payloadBytes = canonical(parts[1], 8192);
  const signature = canonical(parts[2], 256);
  if (!headerBytes || !payloadBytes || !signature || signature.length !== 64)
    throw new Error("Verification receipt encoding is invalid.");
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = JSON.parse(headerBytes.toString("utf8"));
    claims = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    throw new Error("Verification receipt is invalid.");
  }
  if (
    header.alg !== "Ed25519" ||
    header.typ !== "portkey-verification+jwt" ||
    typeof header.kid !== "string" ||
    Object.keys(header).sort().join(",") !== "alg,kid,typ"
  )
    throw new Error("Verification receipt algorithm is not accepted.");
  let keys = await pinnedJwks(origin);
  let jwk = keys.find((value): value is Record<string, unknown> =>
    Boolean(value && typeof value === "object" && (value as Record<string, unknown>).kid === header.kid),
  );
  if (!jwk) {
    keys = await pinnedJwks(origin, true);
    jwk = keys.find((value): value is Record<string, unknown> =>
      Boolean(value && typeof value === "object" && (value as Record<string, unknown>).kid === header.kid),
    );
  }
  if (
    !jwk ||
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    jwk.alg !== "Ed25519" ||
    jwk.use !== "sig" ||
    typeof jwk.x !== "string" ||
    "d" in jwk ||
    Object.keys(jwk).sort().join(",") !== "alg,crv,kid,kty,use,x"
  )
    throw new Error("Portkey signing key is not accepted.");
  const key = createPublicKey({
    key: jwk as import("node:crypto").JsonWebKey,
    format: "jwk",
  });
  if (
    !verifySignature(
      null,
      Buffer.from(`${parts[0]}.${parts[1]}`),
      key,
      signature,
    )
  )
    throw new Error("Verification receipt signature is invalid.");

  const allowed = [
    "aud",
    "contract_digest",
    "contract_id",
    "contract_version",
    "exp",
    "iat",
    "iss",
    "jti",
    "request_id",
    "result",
  ];
  if (
    Object.keys(claims).sort().join(",") !== allowed.join(",") ||
    claims.result !== true ||
    claims.iss !== origin ||
    claims.aud !== expected.audience ||
    claims.request_id !== expected.requestId ||
    claims.contract_id !== expected.contractId ||
    claims.contract_version !== expected.contractVersion ||
    claims.contract_digest !== expected.contractDigest ||
    typeof claims.jti !== "string" ||
    !uuid.test(claims.jti) ||
    typeof claims.iat !== "number" ||
    !Number.isSafeInteger(claims.iat) ||
    typeof claims.exp !== "number" ||
    !Number.isSafeInteger(claims.exp) ||
    !digest.test(String(claims.contract_digest))
  )
    throw new Error("Verification receipt does not match this request.");
  const now = expected.now ?? Math.floor(Date.now() / 1000);
  if (
    claims.exp <= now - 30 ||
    claims.iat > now + 30 ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > 300
  )
    throw new Error(
      "Verification receipt has expired or is outside its validity period.",
    );
  return claims as unknown as ReceiptClaims;
}
