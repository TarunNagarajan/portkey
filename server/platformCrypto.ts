import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import type { Database, Queries } from './database.js';

const b64 = (value: Buffer) => value.toString('base64url');
const sha = (value: string) => createHash('sha256').update(value).digest('base64url');

export async function signingKey(database: Database | Queries) {
  let [row] = await database.query<{ kid: string; private_pkcs8: Buffer; public_spki: Buffer }>(
    'SELECT kid, private_pkcs8, public_spki FROM platform_signing_keys WHERE singleton = TRUE',
  );
  if (!row) {
    const pair = generateKeyPairSync('ed25519');
    const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const candidate = { kid: `portkey-${randomUUID()}`, privateDer, publicDer };
    await database.query(
      `INSERT INTO platform_signing_keys(singleton, kid, private_pkcs8, public_spki)
       VALUES(TRUE,$1,$2,$3) ON CONFLICT(singleton) DO NOTHING`,
      [candidate.kid, candidate.privateDer, candidate.publicDer],
    );
    [row] = await database.query<{ kid: string; private_pkcs8: Buffer; public_spki: Buffer }>(
      'SELECT kid, private_pkcs8, public_spki FROM platform_signing_keys WHERE singleton = TRUE',
    );
  }
  if (!row) throw new Error('Receipt signing key could not be initialized.');
  return {
    kid: row.kid,
    privateKey: createPrivateKey({ key: row.private_pkcs8, format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: row.public_spki, format: 'der', type: 'spki' }),
  };
}

export async function publicJwks(database: Database) {
  const key = await signingKey(database);
  const jwk = key.publicKey.export({ format: 'jwk' });
  return { keys: [{ kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: key.kid, use: 'sig', alg: 'Ed25519' }] };
}

export async function issueReceipt(database: Database, claims: Record<string, unknown>) {
  const key = await signingKey(database);
  return signCompactJws(key.kid, key.privateKey, claims);
}

export function signCompactJws(kid: string, privateKey: import('node:crypto').KeyObject, claims: Record<string, unknown>) {
  const header = b64(Buffer.from(JSON.stringify({ alg: 'Ed25519', typ: 'portkey-verification+jwt', kid })));
  const payload = b64(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), privateKey).toString('base64url')}`;
}

export { sha as pkceS256 };
