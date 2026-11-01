import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { openDatabase } from '../server/database.js';
import { migrate } from '../server/migrations.js';
import { publicJwks, rotateSigningKey, signCompactJws, signingKey } from '../server/platformCrypto.js';
import { verifyReceipt } from '../sdk/index.js';

async function ageActiveKey(database: Awaited<ReturnType<typeof openDatabase>>) {
  await database.query("UPDATE platform_signing_keyring SET created_at=clock_timestamp()-interval '61 seconds' WHERE active=TRUE");
}

test('rotation retains public verification keys, erases retired private material and enforces the JWKS bound', async () => {
  const database = await openDatabase();
  try {
    await migrate(database);
    const original = await signingKey(database);
    const before = await publicJwks(database);
    assert.equal(before.keys.length, 1);
    assert.equal(before.keys[0]?.kid, original.kid);

    await ageActiveKey(database);
    const nextKid = await rotateSigningKey(database);
    const after = await publicJwks(database);
    assert.equal(after.keys.length, 2);
    assert(after.keys.some((key) => key.kid === original.kid));
    assert(after.keys.some((key) => key.kid === nextKid));
    const [retired] = await database.query<{ private_pkcs8: Buffer | null; verify_until: Date }>(
      'SELECT private_pkcs8,verify_until FROM platform_signing_keyring WHERE kid=$1',
      [original.kid],
    );
    assert.equal(retired.private_pkcs8, null);
    assert(retired.verify_until.getTime() > Date.now());

    await database.query(`UPDATE platform_signing_keyring SET verify_until=clock_timestamp()+interval '10 minutes' WHERE active=FALSE`);
    for (let index = 0; index < 6; index += 1) {
      await ageActiveKey(database);
      await rotateSigningKey(database);
    }
    await ageActiveKey(database);
    await assert.rejects(rotateSigningKey(database), /capacity/);
    assert.equal((await publicJwks(database)).keys.length, 8);
  } finally {
    await database.close();
  }
});

test('concurrent initializers converge on one active key', async () => {
  const database = await openDatabase();
  try {
    await migrate(database);
    const keys = await Promise.all(Array.from({ length: 6 }, () => signingKey(database)));
    assert.equal(new Set(keys.map((key) => key.kid)).size, 1);
    const [active] = await database.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM platform_signing_keyring WHERE active=TRUE',
    );
    assert.equal(active.count, 1);
  } finally {
    await database.close();
  }
});

test('concurrent rotations serialize to one active key', async () => {
  const database = await openDatabase();
  try {
    await migrate(database);
    await signingKey(database);
    await ageActiveKey(database);
    const rotations = await Promise.allSettled([rotateSigningKey(database), rotateSigningKey(database)]);
    assert.equal(rotations.filter((rotation) => rotation.status === 'fulfilled').length, 1);
    assert.equal(rotations.filter((rotation) => rotation.status === 'rejected').length, 1);
    const [active] = await database.query<{ kid: string; count: number }>(
      'SELECT kid,count(*) OVER()::int AS count FROM platform_signing_keyring WHERE active=TRUE',
    );
    assert.equal(active.count, 1);
    assert(rotations.some((rotation) => rotation.status === 'fulfilled' && rotation.value === active.kid));
  } finally {
    await database.close();
  }
});

test('legacy singleton migration preserves its signing key', async () => {
  const database = await openDatabase();
  try {
    const pair = generateKeyPairSync('ed25519');
    const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const createdAt = new Date('2020-01-02T03:04:05.000Z');
    await database.exec(`CREATE TABLE platform_signing_keys (
      singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton), kid TEXT NOT NULL UNIQUE,
      private_pkcs8 BYTEA NOT NULL, public_spki BYTEA NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`);
    await database.query('INSERT INTO platform_signing_keys(singleton,kid,private_pkcs8,public_spki,created_at) VALUES(TRUE,$1,$2,$3,$4)',
      ['legacy-kid', privateDer, publicDer, createdAt]);
    const sql = await readFile(new URL('../server/migrations/014_signing_key_rotation.sql', import.meta.url), 'utf8');
    await database.exec(sql);
    const [row] = await database.query<{ kid: string; private_pkcs8: Uint8Array; public_spki: Uint8Array; created_at: Date }>(
      'SELECT kid,private_pkcs8,public_spki,created_at FROM platform_signing_keyring WHERE active=TRUE');
    assert.equal(row.kid, 'legacy-kid');
    assert.deepEqual(Buffer.from(row.private_pkcs8), privateDer);
    assert.deepEqual(Buffer.from(row.public_spki), publicDer);
    assert.equal(row.created_at.getTime(), createdAt.getTime());
  } finally {
    await database.close();
  }
});

test('receipts verify across live rotation and retired keys stop verifying after expiry', async () => {
  const database = await openDatabase();
  const origin = 'https://live-rotation.test';
  const expiredOrigin = 'https://expired-rotation.test';
  const originalFetch = globalThis.fetch;
  let liveFetches = 0;
  let expiredFetches = 0;
  try {
    await migrate(database);
    const oldKey = await signingKey(database);
    const now = Math.floor(Date.now() / 1000);
    const expectation = {
      issuer: origin,
      audience: '11111111-1111-4111-8111-111111111111',
      requestId: '44444444-4444-4444-8444-444444444444',
      contractId: '22222222-2222-4222-8222-222222222222',
      contractVersion: 1,
      contractDigest: 'a'.repeat(64),
      now,
    };
    const makeReceipt = (key: Awaited<ReturnType<typeof signingKey>>, issuer = origin) =>
      signCompactJws(key.kid, key.privateKey, {
        iss: issuer,
        aud: expectation.audience,
        jti: randomUUID(),
        request_id: expectation.requestId,
        contract_id: expectation.contractId,
        contract_version: expectation.contractVersion,
        contract_digest: expectation.contractDigest,
        result: true,
        iat: now,
        exp: now + 300,
      });
    const oldReceipt = makeReceipt(oldKey);

    await ageActiveKey(database);
    await rotateSigningKey(database);
    const newKey = await signingKey(database);
    const newReceipt = makeReceipt(newKey);
    const oldReceiptForFreshOrigin = makeReceipt(oldKey, expiredOrigin);
    const newReceiptForFreshOrigin = makeReceipt(newKey, expiredOrigin);
    globalThis.fetch = async (input) => {
      const requestUrl = String(input);
      if (requestUrl.startsWith(`${origin}/`)) liveFetches += 1;
      else expiredFetches += 1;
      return new Response(JSON.stringify(await publicJwks(database)), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const oldClaims = await verifyReceipt(oldReceipt, expectation);
    const newClaims = await verifyReceipt(newReceipt, expectation);
    assert.equal(oldClaims.jti, JSON.parse(Buffer.from(oldReceipt.split('.')[1]!, 'base64url').toString()).jti);
    assert.equal(newClaims.jti, JSON.parse(Buffer.from(newReceipt.split('.')[1]!, 'base64url').toString()).jti);
    assert.equal(liveFetches, 1);

    const [header, payload, signature] = oldReceipt.split('.');
    const alteredSignature = `${signature![0] === 'A' ? 'B' : 'A'}${signature!.slice(1)}`;
    await assert.rejects(verifyReceipt(`${header}.${payload}.${alteredSignature}`, expectation), /signature is invalid/);
    assert.equal(liveFetches, 1);

    await database.query(
      "UPDATE platform_signing_keyring SET verify_until=clock_timestamp()-interval '1 second' WHERE kid=$1",
      [oldKey.kid],
    );
    const freshExpectation = { ...expectation, issuer: expiredOrigin };
    await assert.rejects(verifyReceipt(oldReceiptForFreshOrigin, freshExpectation), /signing key is not accepted/);
    assert.equal(expiredFetches, 2);
    const currentClaims = await verifyReceipt(newReceiptForFreshOrigin, freshExpectation);
    assert.equal(currentClaims.contract_id, expectation.contractId);
    assert.equal(expiredFetches, 2);
  } finally {
    globalThis.fetch = originalFetch;
    await database.close();
  }
});

test('SDK refreshes once for an unknown key and verifies a receipt with that key', async () => {
  const oldPair = generateKeyPairSync('ed25519');
  const newPair = generateKeyPairSync('ed25519');
  const jwk = (kid: string, publicKey: typeof oldPair.publicKey) => {
    const value = publicKey.export({ format: 'jwk' });
    return { kty: 'OKP', crv: 'Ed25519', x: value.x, kid, use: 'sig', alg: 'Ed25519' };
  };
  const receipt = signCompactJws('new-key', newPair.privateKey, {
    iss: 'https://rotation.test', aud: '11111111-1111-4111-8111-111111111111',
    jti: '33333333-3333-4333-8333-333333333333', request_id: '44444444-4444-4444-8444-444444444444',
    contract_id: '22222222-2222-4222-8222-222222222222', contract_version: 1,
    contract_digest: 'a'.repeat(64), result: true, iat: 1_700_000_000, exp: 1_700_000_300,
  });
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    const keys = calls === 1 ? [jwk('old-key', oldPair.publicKey)] : [jwk('new-key', newPair.publicKey)];
    return new Response(JSON.stringify({ keys }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const expectation = {
      issuer: 'https://rotation.test', audience: '11111111-1111-4111-8111-111111111111',
      requestId: '44444444-4444-4444-8444-444444444444', contractId: '22222222-2222-4222-8222-222222222222',
      contractVersion: 1, contractDigest: 'a'.repeat(64), now: 1_700_000_000,
    };
    const accepted = await Promise.all(Array.from({ length: 8 }, () => verifyReceipt(receipt, expectation)));
    assert(accepted.every((claims) => claims.jti === '33333333-3333-4333-8333-333333333333'));
    assert.equal(calls, 2);

    const unknownReceipt = signCompactJws('other-unknown-key', newPair.privateKey, {
      iss: 'https://rotation.test', aud: expectation.audience,
      jti: '33333333-3333-4333-8333-333333333333', request_id: expectation.requestId,
      contract_id: expectation.contractId, contract_version: 1,
      contract_digest: expectation.contractDigest, result: true, iat: 1_700_000_000, exp: 1_700_000_300,
    });
    const rejected = await Promise.allSettled(Array.from({ length: 8 }, () => verifyReceipt(unknownReceipt, expectation)));
    assert(rejected.every((result) => result.status === 'rejected'));
    assert.equal(calls, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
