import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import supertest from 'supertest';
import type { Express } from 'express';
import { createPortkeyClient } from '../sdk/index.js';
import { createApp } from '../server/app.js';
import { openDatabase, type Database } from '../server/database.js';
import { migrate } from '../server/migrations.js';

const root = process.cwd();
const fixture = resolve(root, 'tests/fixtures/groth16-testonly');
const generator = resolve(root, 'examples/groth16-bn254-testonly/generate.mjs');
const signals = ['challenge', 'eligibility result', 'nullifier'];
const scalarField = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const baseField = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

let origin = '';
let relyingOrigin = '';
let appId = '';
let domainChallenge = '';
let database: Database;
let app: Express;
let walletServer: Server;
let domainServer: Server;
let databaseDirectory = '';

before(async () => {
  const probe = createServer();
  await new Promise<void>(resolveListen => probe.listen(0, '127.0.0.1', () => resolveListen()));
  const address = probe.address();
  assert(address && typeof address === 'object');
  await new Promise<void>(resolveClose => probe.close(() => resolveClose()));
  origin = `http://127.0.0.1:${address.port}`;
  databaseDirectory = await mkdtemp(join(tmpdir(), 'portkey-groth16-test-'));
  database = await openDatabase({ dataDir: databaseDirectory });
  await migrate(database);
  app = createApp(database, { origin, secure: false, rateLimiting: false });
  walletServer = createServer(app);
  await new Promise<void>((resolveListen, reject) => {
    walletServer.once('error', reject);
    walletServer.listen(address.port, '127.0.0.1', () => { walletServer.off('error', reject); resolveListen(); });
  });
  domainServer = createServer((request, response) => {
    if (request.url !== '/.well-known/portkey-app.json') { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ appId, challenge: domainChallenge }));
  });
  await new Promise<void>((resolveListen, reject) => {
    domainServer.once('error', reject);
    domainServer.listen(0, '127.0.0.1', () => { domainServer.off('error', reject); resolveListen(); });
  });
  const domainAddress = domainServer.address();
  assert(domainAddress && typeof domainAddress === 'object');
  relyingOrigin = `http://127.0.0.1:${domainAddress.port}`;
});

after(async () => {
  for (const server of [domainServer, walletServer]) if (server?.listening) await new Promise<void>(resolveClose => server.close(() => resolveClose()));
  if (database) await database.close();
  if (databaseDirectory) await rm(databaseDirectory, { recursive: true, force: true });
});

async function browser() {
  const agent = supertest.agent(app);
  const session = await agent.post('/api/session').set('Origin', origin).expect(200);
  const csrf = session.body.csrfToken as string;
  return {
    agent,
    get: (path: string) => agent.get(`/api${path}`),
    post: (path: string, body: object = {}) => agent.post(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
    put: (path: string, body: object = {}) => agent.put(`/api${path}`).set('Origin', origin).set('X-CSRF-Token', csrf).send(body),
  };
}

async function customProof(wallet: Awaited<ReturnType<typeof browser>>, client: ReturnType<typeof createPortkeyClient>, contractId: string, contractVersion: number, zkeyName = 'eligibility.zkey', nullifier = '42') {
  const request = await client.createProofRequest({ contractId, contractVersion, redirectUri: `${relyingOrigin}/callback` });
  const capability = new URLSearchParams(new URL(request.walletUrl).hash.slice(1)).get('request');
  assert(capability);
  const descriptor = await wallet.post(`/platform/wallet/proof-requests/${request.requestId}/lookup`, { capability }).expect(200);
  assert.equal(descriptor.body.contract.adapter, 'groth16-bn254-v1');
  const challenge = (await wallet.post(`/platform/wallet/proof-requests/${request.requestId}/challenge`, { capability }).expect(200)).body as {
    adapter: string; challengeId: string; challenge: string; adapterFingerprint: string; expiresAt: string;
  };
  assert.equal(challenge.adapter, 'groth16-bn254-v1');
  assert(BigInt(challenge.challenge) > 0n && BigInt(challenge.challenge) < scalarField);
  const proofPath = join(databaseDirectory, `proof-${request.requestId}.json`);
  const provingKey = resolve(fixture, zkeyName);
  const generated = spawnSync(process.execPath, [generator, challenge.challenge, resolve(fixture, 'eligibility.wasm'), provingKey, proofPath, nullifier], { cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  assert.equal(generated.status, 0, generated.stderr || generated.stdout || 'Groth16 proof generation failed.');
  const proof = JSON.parse(await readFile(proofPath, 'utf8')) as { proof: Record<string, unknown>; publicSignals: string[] };
  assert.deepEqual(proof.publicSignals, [challenge.challenge, '1', nullifier]);
  return { request, capability, challenge, proof, proofPath };
}

test('a pinned Groth16 key verifies real challenge-bound proofs through receipt exchange', async () => {
  const issuer = await browser();
  const appOwner = await browser();
  const wallet = await browser();
  const verificationKey = JSON.parse(await readFile(resolve(fixture, 'verification_key.json'), 'utf8')) as Record<string, unknown>;
  const alternateKey = JSON.parse(await readFile(resolve(fixture, 'verification_key_alt.json'), 'utf8')) as Record<string, unknown>;
  const common = { issuerLabel: 'Local test issuer', description: 'A public test circuit with a deliberately unsafe test ceremony.', adapter: 'groth16-bn254-v1', groupIds: [], publicSignalNames: signals };
  const unauthenticatedLarge = await issuer.agent.post('/api/platform/contracts').set('Origin', origin).send({ name: 'No CSRF', ...common, verificationKey: { ...verificationKey, extra: 'x'.repeat(10_000) } });
  assert.equal(unauthenticatedLarge.status, 403);
  const oversizedKnownBody = await issuer.post('/platform/contracts', { name: 'Over limit', ...common, verificationKey: { ...verificationKey, extra: 'x'.repeat(42_000) } });
  assert.equal(oversizedKnownBody.status, 413);
  await issuer.post('/platform/contracts', { name: 'Invalid extra key', ...common, verificationKey: { ...verificationKey, extra: 'x'.repeat(10_000) } }).expect(422);
  const contractResponse = await issuer.post('/platform/contracts', {
    name: 'Test-only Groth16', issuerLabel: 'Local test issuer', description: 'A public test circuit with a deliberately unsafe test ceremony.',
    adapter: 'groth16-bn254-v1', groupIds: [], verificationKey, publicSignalNames: signals,
  });
  assert.equal(contractResponse.status, 201, JSON.stringify(contractResponse.body));
  const contract = contractResponse.body as { id: string; version: number; digest: string; adapterConfig: { fingerprint: string } };
  const alternate = (await issuer.post('/platform/contracts', {
    name: 'Alternate test key', issuerLabel: 'Local test issuer', description: 'Same test circuit, different proving key.',
    adapter: 'groth16-bn254-v1', groupIds: [], verificationKey: alternateKey, publicSignalNames: signals,
  }).expect(201)).body as { id: string; version: number; digest: string };

  const registered = (await appOwner.post('/platform/apps', {
    name: 'Groth16 relying app', origin: relyingOrigin, redirectUris: [`${relyingOrigin}/callback`],
  }).expect(201)).body as { id: string; apiKey: string };
  appId = registered.id;
  domainChallenge = (await appOwner.post(`/platform/apps/${registered.id}/domain-challenge`, {}).expect(200)).body.challenge as string;
  await appOwner.post(`/platform/apps/${registered.id}/verify-domain`, {}).expect(200);
  await appOwner.put(`/platform/apps/${registered.id}/trust`, { contracts: [
    { contractId: contract.id, version: contract.version }, { contractId: alternate.id, version: alternate.version },
  ] }).expect(200);
  const client = createPortkeyClient({ origin, apiKey: registered.apiKey, appId: registered.id });

  const first = await customProof(wallet, client, contract.id, contract.version);
  assert.equal(first.challenge.adapterFingerprint, contract.adapterConfig.fingerprint);

  const wrongChallenge = structuredClone(first.proof);
  wrongChallenge.publicSignals[0] = first.challenge.challenge === '2' ? '3' : '2';
  await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/prove`, { capability: first.capability, challengeId: first.challenge.challengeId, proof: wrongChallenge }).expect(403);

  const extraSignal = structuredClone(first.proof);
  extraSignal.publicSignals.push('9');
  await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/prove`, { capability: first.capability, challengeId: first.challenge.challengeId, proof: extraSignal }).expect(403);

  const malformed = structuredClone(first.proof);
  (malformed.proof.pi_a as string[])[2] = '2';
  await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/prove`, { capability: first.capability, challengeId: first.challenge.challengeId, proof: malformed }).expect(422);

  const tampered = structuredClone(first.proof);
  const originalX = BigInt((tampered.proof.pi_c as string[])[0]);
  (tampered.proof.pi_c as string[])[0] = (originalX + 1n < baseField ? originalX + 1n : originalX - 1n).toString();
  await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/prove`, { capability: first.capability, challengeId: first.challenge.challengeId, proof: tampered }).expect(403);

  const staged = await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/prove`, { capability: first.capability, challengeId: first.challenge.challengeId, proof: first.proof }).expect(200);
  assert.equal(staged.body.approved, false);
  assert.deepEqual(staged.body.disclosedSignals, [
    { name: 'challenge', value: first.challenge.challenge }, { name: 'eligibility result', value: '1' }, { name: 'nullifier', value: '42' },
  ]);
  await supertest(app).get(`/v1/proof-requests/${first.request.requestId}`).set('Authorization', `Bearer ${registered.apiKey}`).expect(200).expect(response => assert.equal(response.body.status, 'pending'));
  await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/approve-custom-proof`, { capability: first.capability }).expect(200);
  const approvalRetry = await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/approve-custom-proof`, { capability: first.capability }).expect(200);
  assert.equal(approvalRetry.body.alreadyApproved, true, 'A lost approval response can be retried by the same wallet.');
  await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/prove`, { capability: first.capability, challengeId: first.challenge.challengeId, proof: first.proof }).expect(403);
  await supertest(app).get(`/v1/proof-requests/${first.request.requestId}`).set('Authorization', `Bearer ${registered.apiKey}`).expect(200).expect(response => assert.equal(response.body.status, 'verified'));
  const returned = (await wallet.post(`/platform/wallet/proof-requests/${first.request.requestId}/return`, { capability: first.capability }).expect(200)).body as { redirectUrl: string };
  const code = new URLSearchParams(new URL(returned.redirectUrl).hash.slice(1)).get('code');
  assert(code);
  const firstReceipt = await client.exchange(first.request.requestId, code, first.request.codeVerifier, { contractId: contract.id, contractVersion: contract.version, contractDigest: contract.digest });
  assert.equal((await client.verifyReceipt(firstReceipt.receipt, { requestId: first.request.requestId, contractId: contract.id, contractVersion: contract.version, contractDigest: contract.digest })).result, true);

  const wrongKeyRequest = await client.createProofRequest({ contractId: alternate.id, contractVersion: alternate.version, redirectUri: `${relyingOrigin}/callback` });
  const wrongKeyCapability = new URLSearchParams(new URL(wrongKeyRequest.walletUrl).hash.slice(1)).get('request');
  assert(wrongKeyCapability);
  const wrongKeyChallenge = (await wallet.post(`/platform/wallet/proof-requests/${wrongKeyRequest.requestId}/challenge`, { capability: wrongKeyCapability }).expect(200)).body as typeof first.challenge;
  const wrongKeyPath = join(databaseDirectory, 'wrong-key-proof.json');
  const mismatched = spawnSync(process.execPath, [generator, wrongKeyChallenge.challenge, resolve(fixture, 'eligibility.wasm'), resolve(fixture, 'eligibility.zkey'), wrongKeyPath, '43'], { cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  assert.equal(mismatched.status, 0, mismatched.stderr || mismatched.stdout || 'Wrong-key proof generation failed.');
  const proofForOtherKey = JSON.parse(await readFile(wrongKeyPath, 'utf8'));
  await wallet.post(`/platform/wallet/proof-requests/${wrongKeyRequest.requestId}/prove`, { capability: wrongKeyCapability, challengeId: wrongKeyChallenge.challengeId, proof: proofForOtherKey }).expect(403);
  const alternatePath = join(databaseDirectory, 'alternate-proof.json');
  const alternateGenerated = spawnSync(process.execPath, [generator, wrongKeyChallenge.challenge, resolve(fixture, 'eligibility.wasm'), resolve(fixture, 'eligibility-alt.zkey'), alternatePath, '42'], { cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  assert.equal(alternateGenerated.status, 0, alternateGenerated.stderr || alternateGenerated.stdout || 'Alternate Groth16 proof generation failed.');
  const alternateProof = JSON.parse(await readFile(alternatePath, 'utf8'));
  const alternateStage = await wallet.post(`/platform/wallet/proof-requests/${wrongKeyRequest.requestId}/prove`, { capability: wrongKeyCapability, challengeId: wrongKeyChallenge.challengeId, proof: alternateProof }).expect(200);
  assert.equal(alternateStage.body.disclosedSignals[2].value, '42');
  await wallet.post(`/platform/wallet/proof-requests/${wrongKeyRequest.requestId}/approve-custom-proof`, { capability: wrongKeyCapability }).expect(200);
  const alternateReturn = (await wallet.post(`/platform/wallet/proof-requests/${wrongKeyRequest.requestId}/return`, { capability: wrongKeyCapability }).expect(200)).body as { redirectUrl: string };
  const alternateCode = new URLSearchParams(new URL(alternateReturn.redirectUrl).hash.slice(1)).get('code');
  assert(alternateCode);
  const alternateReceipt = await client.exchange(wrongKeyRequest.requestId, alternateCode, wrongKeyRequest.codeVerifier, { contractId: alternate.id, contractVersion: alternate.version, contractDigest: alternate.digest });
  assert.equal((await client.verifyReceipt(alternateReceipt.receipt, { requestId: wrongKeyRequest.requestId, contractId: alternate.id, contractVersion: alternate.version, contractDigest: alternate.digest })).result, true);

  const nextVersion = (await issuer.post(`/platform/contracts/${contract.id}/versions`, {
    description: 'Version 2 with the same verifier data.', adapter: 'groth16-bn254-v1', groupIds: [], verificationKey, publicSignalNames: signals,
  }).expect(201)).body as { version: number; digest: string };
  await appOwner.put(`/platform/apps/${registered.id}/trust`, { contracts: [
    { contractId: contract.id, version: contract.version }, { contractId: contract.id, version: nextVersion.version }, { contractId: alternate.id, version: alternate.version },
  ] }).expect(200);
  const sameNullifierOtherVersion = await customProof(wallet, client, contract.id, nextVersion.version);
  assert.equal(sameNullifierOtherVersion.proof.publicSignals[2], '42');
  const versionStage = await wallet.post(`/platform/wallet/proof-requests/${sameNullifierOtherVersion.request.requestId}/prove`, { capability: sameNullifierOtherVersion.capability, challengeId: sameNullifierOtherVersion.challenge.challengeId, proof: sameNullifierOtherVersion.proof }).expect(200);
  assert.equal(versionStage.body.approved, false);
  await wallet.post(`/platform/wallet/proof-requests/${sameNullifierOtherVersion.request.requestId}/approve-custom-proof`, { capability: sameNullifierOtherVersion.capability }).expect(200);

  const duplicateNullifier = await customProof(wallet, client, contract.id, contract.version);
  const duplicateStage = await wallet.post(`/platform/wallet/proof-requests/${duplicateNullifier.request.requestId}/prove`, { capability: duplicateNullifier.capability, challengeId: duplicateNullifier.challenge.challengeId, proof: duplicateNullifier.proof }).expect(200);
  assert.equal(duplicateStage.body.approved, false);
  await wallet.post(`/platform/wallet/proof-requests/${duplicateNullifier.request.requestId}/approve-custom-proof`, { capability: duplicateNullifier.capability }).expect(403);

  const revokedRequest = await customProof(wallet, client, alternate.id, alternate.version, 'eligibility-alt.zkey', '43');
  await wallet.post(`/platform/wallet/proof-requests/${revokedRequest.request.requestId}/prove`, { capability: revokedRequest.capability, challengeId: revokedRequest.challenge.challengeId, proof: revokedRequest.proof }).expect(200);
  await appOwner.put(`/platform/apps/${registered.id}/trust`, { contracts: [
    { contractId: contract.id, version: contract.version }, { contractId: contract.id, version: nextVersion.version },
  ] }).expect(200);
  await wallet.post(`/platform/wallet/proof-requests/${revokedRequest.request.requestId}/approve-custom-proof`, { capability: revokedRequest.capability }).expect(403);

  const latest = await issuer.get(`/platform/contracts/${contract.id}/versions`).expect(200);
  assert.equal(latest.body.versions.find((item: { version: number }) => item.version === nextVersion.version).adapter, 'groth16-bn254-v1');
  assert.equal(latest.body.versions.find((item: { version: number }) => item.version === nextVersion.version).adapter_config.fingerprint, contract.adapterConfig.fingerprint);

  const tooLargeLegacy = await issuer.post('/credential-groups', { name: 'x'.repeat(9_000), description: '' });
  assert.equal(tooLargeLegacy.status, 413);
});
