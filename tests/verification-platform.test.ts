import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import supertest from "supertest";
import type { Express } from "express";
import { Identity } from "@semaphore-protocol/identity";
import { createPortkeyClient, createPKCE } from "../sdk/index.js";
import { createApp } from "../server/app.js";
import { openDatabase, type Database } from "../server/database.js";
import { migrate } from "../server/migrations.js";

let origin = "";
let database: Database;
let app: Express;
let walletServer: Server;
let domainServer: Server;
let databaseDirectory = "";

before(async () => {
  const probe = createServer();
  await new Promise<void>((resolve) =>
    probe.listen(0, "127.0.0.1", () => resolve()),
  );
  const address = probe.address();
  assert(address && typeof address === "object");
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  origin = `http://127.0.0.1:${address.port}`;
  databaseDirectory = await mkdtemp(join(tmpdir(), "portkey-platform-test-"));
  database = await openDatabase({ dataDir: databaseDirectory });
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
  walletServer = createServer(app);
  await new Promise<void>((resolve, reject) => {
    walletServer.once("error", reject);
    walletServer.listen(address.port, "127.0.0.1", () => {
      walletServer.off("error", reject);
      resolve();
    });
  });
  domainServer = createServer((request, response) => {
    if (request.url !== "/.well-known/portkey-app.json") {
      response.writeHead(404).end();
      return;
    }
    const challenge = domainChallenge;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ appId, challenge }));
  });
  await new Promise<void>((resolve, reject) => {
    domainServer.once("error", reject);
    domainServer.listen(0, "127.0.0.1", () => {
      domainServer.off("error", reject);
      resolve();
    });
  });
  const domainAddress = domainServer.address();
  assert(domainAddress && typeof domainAddress === "object");
  relyingOrigin = `http://127.0.0.1:${domainAddress.port}`;
});

after(async () => {
  for (const server of [domainServer, walletServer]) {
    if (server?.listening)
      await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  const curve = (
    globalThis as typeof globalThis & {
      curve_bn128?: { terminate: () => Promise<void> };
    }
  ).curve_bn128;
  if (curve) await curve.terminate();
  if (database) await database.close();
  if (databaseDirectory)
    await rm(databaseDirectory, { recursive: true, force: true });
});

let appId = "";
let domainChallenge = "";
let relyingOrigin = "";

async function browser() {
  const agent = supertest.agent(app);
  const response = await agent
    .post("/api/session")
    .set("Origin", origin)
    .expect(200);
  const csrf = response.body.csrfToken as string;
  return {
    agent,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) =>
      agent
        .post(`/api${path}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send(body),
    put: (path: string, body: object = {}) =>
      agent
        .put(`/api${path}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send(body),
  };
}

test("different-owner contract, controlled domain, genuine ZK proof, PKCE exchange and signed receipt work end to end", async () => {
  const issuer = await browser();
  const appOwner = await browser();
  const wallet = await browser();
  const secondWallet = await browser();

  const group = (
    await issuer
      .post("/credential-groups", {
        name: "Independent issuer members",
        description: "",
      })
      .expect(201)
  ).body as { id: string };
  const invite = (
    await issuer
      .post(`/credential-groups/${group.id}/enrollments`, { count: 2 })
      .expect(201)
  ).body.enrollments as Array<{ token: string }>;
  const contract = (
    await issuer
      .post("/platform/contracts", {
        name: "Independent membership",
        issuerLabel: "Self-described issuer",
        description: "Membership in this independently controlled group.",
        groupIds: [group.id],
      })
      .expect(201)
  ).body as { id: string; version: number; digest: string };

  const registered = (
    await appOwner
      .post("/platform/apps", {
        name: "Separate relying app",
        origin: relyingOrigin,
        redirectUris: [`${relyingOrigin}/callback`],
      })
      .expect(201)
  ).body as { id: string; apiKey: string };
  appId = registered.id;
  const challengeResponse = await appOwner
    .post(`/platform/apps/${registered.id}/domain-challenge`, {})
    .expect(200);
  domainChallenge = challengeResponse.body.challenge as string;
  await appOwner
    .post(`/platform/apps/${registered.id}/verify-domain`, {})
    .expect(200);
  await supertest(app)
    .get(`/v1/contracts/${contract.id}/versions/3000000000`)
    .expect(422);
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, {
      contracts: [{ contractId: contract.id, version: 3000000000 }],
    })
    .expect(422);
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, {
      contracts: [{ contractId: contract.id, version: contract.version }],
    })
    .expect(200);
  const [initialPin] = await database.query<{ trust_revision: string }>(
    "SELECT trust_revision FROM platform_app_trust WHERE app_id=$1 AND contract_id=$2 AND contract_version=$3",
    [registered.id, contract.id, contract.version],
  );
  const nextContractVersion = (await issuer
    .post(`/platform/contracts/${contract.id}/versions`, {
      description: "A second immutable version for additive trust testing.",
      groupIds: [group.id],
    })
    .expect(201)).body as { version: number };
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, {
      contracts: [
        { contractId: contract.id, version: contract.version },
        { contractId: contract.id, version: nextContractVersion.version },
      ],
    })
    .expect(200);
  const [preservedPin] = await database.query<{ trust_revision: string }>(
    "SELECT trust_revision FROM platform_app_trust WHERE app_id=$1 AND contract_id=$2 AND contract_version=$3",
    [registered.id, contract.id, contract.version],
  );
  assert.equal(initialPin.trust_revision, preservedPin.trust_revision);

  const [domainExpiry] = await database.query<{ expires_at: Date }>(
    `UPDATE platform_apps SET domain_verified_at=clock_timestamp()-interval '23 hours 58 minutes'
     WHERE id=$1 RETURNING domain_verified_at+interval '24 hours' AS expires_at`,
    [registered.id],
  );

  const identity = new Identity();
  await wallet
    .post(`/credentials/${group.id}/enroll`, {
      token: invite[0].token,
      commitment: identity.commitment.toString(),
    })
    .expect(200);

  const client = createPortkeyClient({
    origin,
    apiKey: registered.apiKey,
    appId: registered.id,
  });
  const request = await client.createProofRequest({
    contractId: contract.id,
    contractVersion: contract.version,
    redirectUri: `${relyingOrigin}/callback`,
  });
  assert(Date.parse(request.expiresAt) <= domainExpiry.expires_at.getTime());

  const [issuerSession] = await database.query<{ id: string }>(
    "SELECT owner_session_id AS id FROM platform_contracts WHERE id=$1",
    [contract.id],
  );
  const [issuerExpiry] = await database.query<{ expires_at: Date }>(
    `UPDATE sessions SET expires_at=clock_timestamp()+interval '45 seconds'
     WHERE id=$1 RETURNING expires_at`,
    [issuerSession.id],
  );
  const issuerClippedRequest = await client.createProofRequest({
    contractId: contract.id,
    contractVersion: contract.version,
    redirectUri: `${relyingOrigin}/callback`,
  });
  assert(
    Date.parse(issuerClippedRequest.expiresAt) <=
      issuerExpiry.expires_at.getTime(),
  );
  await database.query(
    "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
    [issuerSession.id],
  );
  await database.query(
    "UPDATE platform_apps SET domain_verified_at=clock_timestamp() WHERE id=$1",
    [registered.id],
  );
  const walletUrl = new URL(request.walletUrl);
  const capability = new URLSearchParams(walletUrl.hash.slice(1)).get(
    "request",
  );
  assert(capability);
  assert.equal(walletUrl.search, "");
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/lookup`, {
      capability,
    })
    .expect(200)
    .expect(({ body }) => {
      assert.equal(body.contract.groups[0].name, "Independent issuer members");
      assert.equal(
        JSON.stringify(body).includes(identity.commitment.toString()),
        false,
      );
    });
  let challenge = (
    await wallet
      .post(`/platform/wallet/proof-requests/${request.requestId}/challenge`, {
        capability,
      })
      .expect(200)
  ).body as {
    challengeId: string;
    depth: number;
    root: string;
    scope: string;
    message: string;
    commitments: string[];
    expiresAt: string;
  };
  assert.equal(challenge.depth, 10);
  const refreshedChallenge = (
    await wallet
      .post(
        `/platform/wallet/proof-requests/${request.requestId.toUpperCase()}/challenge`,
        { capability },
      )
      .expect(200)
  ).body as typeof challenge;
  assert.equal(refreshedChallenge.scope, challenge.scope);
  assert.notEqual(refreshedChallenge.message, challenge.message);
  challenge = refreshedChallenge;
  const laterIdentity = new Identity();
  await secondWallet
    .post(`/credentials/${group.id}/enroll`, {
      token: invite[1].token,
      commitment: laterIdentity.commitment.toString(),
    })
    .expect(200);
  const semaphoreGroup = new (await import("@semaphore-protocol/group")).Group(
    challenge.commitments.map(BigInt),
  );
  const { generateProof } = await import("@semaphore-protocol/proof");
  const { resolve } = await import("node:path");
  const proof = await generateProof(
    identity,
    semaphoreGroup,
    challenge.message,
    challenge.scope,
    challenge.depth,
    {
      wasm: resolve("public/zk/semaphore-10.wasm"),
      zkey: resolve("public/zk/semaphore-10.zkey"),
    },
  );
  const secondWalletReplay = await secondWallet.post(
    `/platform/wallet/proof-requests/${request.requestId}/prove`,
    { capability, challengeId: challenge.challengeId, proof },
  );
  assert.equal(secondWalletReplay.status, 403);
  const otherCapability = new URLSearchParams(
    new URL(issuerClippedRequest.walletUrl).hash.slice(1),
  ).get("request");
  assert(otherCapability);
  await wallet
    .post(
      `/platform/wallet/proof-requests/${issuerClippedRequest.requestId}/prove`,
      {
        capability: otherCapability,
        challengeId: challenge.challengeId,
        proof,
      },
    )
    .expect(403);
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/prove`, {
      capability,
      challengeId: challenge.challengeId,
      proof,
    })
    .expect(200);
  await database.query(
    "UPDATE platform_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1",
    [request.requestId],
  );
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/prove`, {
      capability,
      challengeId: challenge.challengeId,
      proof,
    })
    .expect(200)
    .expect(({ body }) => assert.equal(body.alreadyVerified, true));
  const returned = (
    await wallet
      .post(`/platform/wallet/proof-requests/${request.requestId}/return`, {
        capability,
      })
      .expect(200)
  ).body as { redirectUrl: string };
  const returnedUrl = new URL(returned.redirectUrl);
  const returnedParameters = new URLSearchParams(returnedUrl.hash.slice(1));
  assert.equal(returnedUrl.origin, relyingOrigin);
  assert.equal(returnedParameters.get("state"), request.state);
  const code = returnedParameters.get("code");
  assert(code);

  const flow = createPKCE();
  assert.equal(flow.state.length, 43);
  assert.equal(flow.verifier.length, 43);
  const expected = {
    contractId: contract.id,
    contractVersion: contract.version,
    contractDigest: contract.digest,
  };
  await assert.rejects(
    client.exchange(request.requestId, code, flow.verifier, expected),
  );
  await assert.rejects(
    client.exchange(
      request.requestId,
      createPKCE().verifier,
      request.codeVerifier,
      expected,
    ),
  );
  await database.query(
    "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    [issuerSession.id],
  );
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/return`, {
      capability,
    })
    .expect(403);
  await supertest(app)
    .post(`/v1/proof-requests/${request.requestId}/exchange`)
    .set("Authorization", `Bearer ${registered.apiKey}`)
    .send({ code, codeVerifier: request.codeVerifier })
    .expect(403);
  await database.query(
    "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
    [issuerSession.id],
  );

  await database.query(
    "UPDATE platform_apps SET domain_verified_at=clock_timestamp()-interval '25 hours' WHERE id=$1",
    [registered.id],
  );
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/return`, {
      capability,
    })
    .expect(401);
  await supertest(app)
    .post(`/v1/proof-requests/${request.requestId}/exchange`)
    .set("Authorization", `Bearer ${registered.apiKey}`)
    .send({ code, codeVerifier: request.codeVerifier })
    .expect(401);
  await database.query(
    "UPDATE platform_apps SET domain_verified_at=clock_timestamp() WHERE id=$1",
    [registered.id],
  );

  const [oldTrust] = await database.query<{ trust_revision: string }>(
    "SELECT trust_revision FROM platform_app_trust WHERE app_id=$1 AND contract_id=$2 AND contract_version=$3",
    [registered.id, contract.id, contract.version],
  );
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, { contracts: [] })
    .expect(200);
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/return`, {
      capability,
    })
    .expect(403);
  await supertest(app)
    .post(`/v1/proof-requests/${request.requestId}/exchange`)
    .set("Authorization", `Bearer ${registered.apiKey}`)
    .send({ code, codeVerifier: request.codeVerifier })
    .expect(403);
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, {
      contracts: [{ contractId: contract.id, version: contract.version }],
    })
    .expect(200);
  const [newTrust] = await database.query<{ trust_revision: string }>(
    "SELECT trust_revision FROM platform_app_trust WHERE app_id=$1 AND contract_id=$2 AND contract_version=$3",
    [registered.id, contract.id, contract.version],
  );
  assert.notEqual(oldTrust.trust_revision, newTrust.trust_revision);
  await wallet
    .post(`/platform/wallet/proof-requests/${request.requestId}/return`, {
      capability,
    })
    .expect(403);
  await supertest(app)
    .post(`/v1/proof-requests/${request.requestId}/exchange`)
    .set("Authorization", `Bearer ${registered.apiKey}`)
    .send({ code, codeVerifier: request.codeVerifier })
    .expect(403);

  const exchangeRequest = await client.createProofRequest({
    contractId: contract.id,
    contractVersion: contract.version,
    redirectUri: `${relyingOrigin}/callback`,
  });
  const exchangeCapability = new URLSearchParams(
    new URL(exchangeRequest.walletUrl).hash.slice(1),
  ).get("request");
  assert(exchangeCapability);
  const exchangeChallenge = (
    await wallet
      .post(
        `/platform/wallet/proof-requests/${exchangeRequest.requestId}/challenge`,
        { capability: exchangeCapability },
      )
      .expect(200)
  ).body as typeof challenge;
  const exchangeGroup = new (await import("@semaphore-protocol/group")).Group(
    exchangeChallenge.commitments.map(BigInt),
  );
  const exchangeProof = await generateProof(
    identity,
    exchangeGroup,
    exchangeChallenge.message,
    exchangeChallenge.scope,
    exchangeChallenge.depth,
    {
      wasm: resolve("public/zk/semaphore-10.wasm"),
      zkey: resolve("public/zk/semaphore-10.zkey"),
    },
  );
  await wallet
    .post(
      `/platform/wallet/proof-requests/${exchangeRequest.requestId}/prove`,
      {
        capability: exchangeCapability,
        challengeId: exchangeChallenge.challengeId,
        proof: exchangeProof,
      },
    )
    .expect(200);
  const exchangeReturn = (
    await wallet
      .post(
        `/platform/wallet/proof-requests/${exchangeRequest.requestId}/return`,
        {
          capability: exchangeCapability,
        },
      )
      .expect(200)
  ).body as { redirectUrl: string };
  const exchangeCallback = new URL(exchangeReturn.redirectUrl);
  const exchangeParameters = new URLSearchParams(
    exchangeCallback.hash.slice(1),
  );
  const exchangeCode = exchangeParameters.get("code");
  assert(exchangeCode);
  assert.equal(exchangeParameters.get("state"), exchangeRequest.state);
  await assert.rejects(
    client.exchange(
      exchangeRequest.requestId,
      exchangeCode,
      flow.verifier,
      expected,
    ),
  );
  await assert.rejects(
    client.exchange(
      exchangeRequest.requestId,
      createPKCE().verifier,
      exchangeRequest.codeVerifier,
      expected,
    ),
  );
  const attempts = await Promise.allSettled([
    client.exchange(
      exchangeRequest.requestId,
      exchangeCode,
      exchangeRequest.codeVerifier,
      expected,
    ),
    client.exchange(
      exchangeRequest.requestId,
      exchangeCode,
      exchangeRequest.codeVerifier,
      expected,
    ),
  ]);
  assert.equal(
    attempts.filter((item) => item.status === "fulfilled").length,
    1,
  );
  const exchangedResult = attempts.find((item) => item.status === "fulfilled");
  assert(exchangedResult && exchangedResult.status === "fulfilled");
  const exchanged = exchangedResult.value;
  assert.equal(exchanged.claims.result, true);
  assert.equal(exchanged.claims.aud, registered.id);
  assert.equal("sub" in exchanged.claims, false);
  assert.equal("nullifier" in exchanged.claims, false);
  assert.equal("commitment" in exchanged.claims, false);

  const oldGenerationRequest = await client.createProofRequest({
    contractId: contract.id,
    contractVersion: contract.version,
    redirectUri: `${relyingOrigin}/callback`,
  });
  const rotated = await appOwner
    .post(`/platform/apps/${registered.id}/rotate-key`, {})
    .expect(200);
  const currentClient = createPortkeyClient({
    origin,
    apiKey: rotated.body.apiKey as string,
    appId: registered.id,
  });
  await supertest(app)
    .get(`/v1/proof-requests/${oldGenerationRequest.requestId}`)
    .set("Authorization", `Bearer ${registered.apiKey}`)
    .expect(401);
  await supertest(app)
    .get(`/v1/proof-requests/${oldGenerationRequest.requestId}`)
    .set("Authorization", `Bearer ${rotated.body.apiKey}`)
    .expect(401);

  const currentGenerationRequest = await currentClient.createProofRequest({
    contractId: contract.id,
    contractVersion: contract.version,
    redirectUri: `${relyingOrigin}/callback`,
  });
  await supertest(app)
    .get(`/v1/proof-requests/${currentGenerationRequest.requestId}`)
    .set("Authorization", `Bearer ${rotated.body.apiKey}`)
    .expect(200);
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, { contracts: [] })
    .expect(200);
  await supertest(app)
    .get(`/v1/proof-requests/${currentGenerationRequest.requestId}`)
    .set("Authorization", `Bearer ${rotated.body.apiKey}`)
    .expect(401);
  await appOwner
    .put(`/platform/apps/${registered.id}/trust`, {
      contracts: [{ contractId: contract.id, version: contract.version }],
    })
    .expect(200);

  const [contractOwner] = await database.query<{ owner_session_id: string }>(
    "SELECT owner_session_id FROM platform_contracts WHERE id=$1",
    [contract.id],
  );
  await database.query(
    "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    [contractOwner.owner_session_id],
  );
  await supertest(app)
    .get(`/v1/proof-requests/${currentGenerationRequest.requestId}`)
    .set("Authorization", `Bearer ${rotated.body.apiKey}`)
    .expect(401);
  await database.query(
    "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
    [contractOwner.owner_session_id],
  );
  await issuer
    .post(
      `/platform/contracts/${contract.id}/versions/${contract.version}/retire`,
      {},
    )
    .expect(200);
  await supertest(app)
    .get(`/v1/proof-requests/${currentGenerationRequest.requestId}`)
    .set("Authorization", `Bearer ${rotated.body.apiKey}`)
    .expect(401);

  await supertest(app)
    .post(`/v1/proof-requests/${request.requestId}/exchange`)
    .set("Authorization", `Bearer ${registered.apiKey}`)
    .send({ code, codeVerifier: request.codeVerifier })
    .expect(401);
  const jwks = (await fetch(`${origin}/v1/.well-known/jwks.json`).then(
    (response) => response.json(),
  )) as { keys: Array<Record<string, unknown>> };
  assert.equal(jwks.keys.length, 1);
  assert.equal("d" in jwks.keys[0], false);
  const [signingKey] = await database.query<{ kid: string }>(
    "SELECT kid FROM platform_signing_keyring WHERE active=TRUE",
  );
  assert.equal(jwks.keys[0].kid, signingKey.kid);

  const serverAddress = walletServer.address();
  assert(serverAddress && typeof serverAddress === "object");
  await new Promise<void>((resolve) => walletServer.close(() => resolve()));
  await database.close();
  database = await openDatabase({ dataDir: databaseDirectory });
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
  walletServer = createServer(app);
  await new Promise<void>((resolve, reject) => {
    walletServer.once("error", reject);
    walletServer.listen(serverAddress.port, "127.0.0.1", () => {
      walletServer.off("error", reject);
      resolve();
    });
  });
  const restartedJwks = (await fetch(`${origin}/v1/.well-known/jwks.json`).then(
    (response) => response.json(),
  )) as { keys: Array<Record<string, unknown>> };
  assert.deepEqual(restartedJwks.keys, jwks.keys);
  const afterRestart = await client.verifyReceipt(exchanged.receipt, {
    requestId: exchangeRequest.requestId,
    contractId: contract.id,
    contractVersion: contract.version,
    contractDigest: contract.digest,
  });
  assert.equal(afterRestart.jti, exchanged.claims.jti);
});
