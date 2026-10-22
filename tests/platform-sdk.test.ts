import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import {
  createPortkeyClient,
  type ReceiptClaims,
  verifyReceipt,
} from "../sdk/index.js";

test("SDK pins configured issuer and audience against runtime expectation overrides", async () => {
  const origin = "http://127.0.0.1:49991";
  const appId = randomUUID();
  const requestId = randomUUID();
  const contractId = randomUUID();
  const contractDigest = "a".repeat(64);
  const kid = randomUUID();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const exported = publicKey.export({ format: "jwk" });
  const jwk = {
    alg: "Ed25519",
    crv: "Ed25519",
    kid,
    kty: "OKP",
    use: "sig",
    x: exported.x,
  };
  const now = Math.floor(Date.now() / 1000);
  const claims: ReceiptClaims = {
    iss: origin,
    aud: appId,
    jti: randomUUID(),
    request_id: requestId,
    contract_id: contractId,
    contract_version: 1,
    contract_digest: contractDigest,
    result: true,
    iat: now,
    exp: now + 120,
  };
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const encodedHeader = encode({
    alg: "Ed25519",
    kid,
    typ: "portkey-verification+jwt",
  });
  const encodedClaims = encode(claims);
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey).toString(
    "base64url",
  );
  const receipt = `${signingInput}.${signature}`;
  const requests: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    requests.push(String(input));
    return new Response(JSON.stringify({ keys: [jwk] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const client = createPortkeyClient({
      origin,
      appId,
      apiKey: `pk_live_${"a".repeat(43)}`,
    });
    const runtimeOverrides = {
      requestId,
      contractId,
      contractVersion: 1,
      contractDigest,
      issuer: "https://attacker.example",
      audience: "attacker-app",
    };
    const verified = await client.verifyReceipt(
      receipt,
      runtimeOverrides as never,
    );
    assert.equal(verified.iss, origin);
    assert.equal(verified.aud, appId);
    assert.deepEqual(requests, [`${origin}/v1/.well-known/jwks.json`]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("SDK cancels oversized chunked JWKS bodies and rejects invalid receipt clocks", async () => {
  const origin = "http://127.0.0.1:49992";
  const validExpected = {
    issuer: origin,
    audience: randomUUID(),
    requestId: randomUUID(),
    contractId: randomUUID(),
    contractVersion: 1,
    contractDigest: "b".repeat(64),
  };
  const encoded = Buffer.from(
    JSON.stringify({
      alg: "Ed25519",
      kid: randomUUID(),
      typ: "portkey-verification+jwt",
    }),
  ).toString("base64url");
  const receipt = `${encoded}.${Buffer.from("{}").toString("base64url")}.${Buffer.alloc(64).toString("base64url")}`;
  let reads = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    reads += 1;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(5_000));
        controller.enqueue(new Uint8Array(5_000));
      },
    });
    return new Response(stream, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  try {
    await assert.rejects(
      verifyReceipt(receipt, { ...validExpected, now: Number.NaN }),
      /expectations are invalid/,
    );
    assert.equal(reads, 0);
    await assert.rejects(
      verifyReceipt(receipt, validExpected),
      /response is too large/,
    );
    assert.equal(reads, 1);
    let declaredLengthAborted = false;
    globalThis.fetch = async (_input, init) => {
      init?.signal?.addEventListener(
        "abort",
        () => {
          declaredLengthAborted = true;
        },
        { once: true },
      );
      return new Response(new ReadableStream<Uint8Array>(), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "9000",
        },
      });
    };
    await assert.rejects(
      verifyReceipt(receipt, validExpected),
      /response is too large/,
    );
    assert.equal(declaredLengthAborted, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("SDK rejects altered receipt metadata, claims and validity using signed fixtures", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const exported = publicKey.export({ format: "jwk" });
  const kid = randomUUID();
  const jwk: Record<string, unknown> = {
    alg: "Ed25519",
    crv: "Ed25519",
    kid,
    kty: "OKP",
    use: "sig",
    x: exported.x,
  };
  const now = Math.floor(Date.now() / 1000);
  let port = 50_100;
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");

  async function rejectsFixture(options: {
    header?: Record<string, unknown>;
    claims?: Record<string, unknown>;
    jwk?: Record<string, unknown>;
    tamperSignature?: boolean;
    expectedError: RegExp;
  }) {
    const origin = `http://127.0.0.1:${port++}`;
    const expected = {
      issuer: origin,
      audience: randomUUID(),
      requestId: randomUUID(),
      contractId: randomUUID(),
      contractVersion: 1,
      contractDigest: "c".repeat(64),
      now,
    };
    const claims = {
      iss: origin,
      aud: expected.audience,
      jti: randomUUID(),
      request_id: expected.requestId,
      contract_id: expected.contractId,
      contract_version: expected.contractVersion,
      contract_digest: expected.contractDigest,
      result: true,
      iat: now,
      exp: now + 120,
      ...options.claims,
    };
    const header = {
      alg: "Ed25519",
      kid,
      typ: "portkey-verification+jwt",
      ...options.header,
    };
    const signingInput = `${encode(header)}.${encode(claims)}`;
    let signatureBytes = sign(null, Buffer.from(signingInput), privateKey);
    if (options.tamperSignature) {
      signatureBytes = Buffer.from(signatureBytes);
      signatureBytes[0] ^= 1;
    }
    const receipt = `${signingInput}.${signatureBytes.toString("base64url")}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [options.jwk ?? jwk] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    try {
      await assert.rejects(
        verifyReceipt(receipt, expected),
        options.expectedError,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  }

  for (const alg of ["none", "HS256", "EdDSA"]) {
    await rejectsFixture({
      header: { alg },
      expectedError: /algorithm is not accepted/,
    });
  }
  await rejectsFixture({
    header: { typ: "JWT" },
    expectedError: /algorithm is not accepted/,
  });
  await rejectsFixture({
    header: { kid: randomUUID() },
    expectedError: /signing key is not accepted/,
  });
  await rejectsFixture({
    jwk: { ...jwk, crv: "X25519" },
    expectedError: /signing key is not accepted/,
  });
  await rejectsFixture({
    tamperSignature: true,
    expectedError: /signature is invalid/,
  });

  for (const claims of [
    { iss: "https://wrong-issuer.example" },
    { aud: randomUUID() },
    { request_id: randomUUID() },
    { contract_id: randomUUID() },
    { contract_version: 2 },
    { contract_digest: "d".repeat(64) },
    { iat: now + 31, exp: now + 120 },
    { iat: now - 100, exp: now - 31 },
    { iat: now, exp: now + 301 },
    { sub: "stable-person-identifier" },
  ]) {
    await rejectsFixture({
      claims,
      expectedError:
        "iss" in claims ||
        "aud" in claims ||
        "request_id" in claims ||
        "contract_id" in claims ||
        "contract_version" in claims ||
        "contract_digest" in claims ||
        "sub" in claims
          ? /does not match this request/
          : /outside its validity period/,
    });
  }
});
