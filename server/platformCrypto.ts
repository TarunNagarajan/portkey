import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import type { Database, Queries } from './database.js';

const b64 = (value: Buffer) => value.toString('base64url');
const sha = (value: string) => createHash('sha256').update(value).digest('base64url');
const keyLimit = 8;
const keyLockId = 742092;
const rotationCooldownSeconds = 60;
type KeyRow = { kid: string; private_pkcs8: Buffer | null; public_spki: Buffer };

async function lockKeyring(queries: Queries) {
  await queries.query('SELECT pg_advisory_xact_lock($1)', [keyLockId]);
}

async function activeRow(queries: Queries) {
  const [row] = await queries.query<KeyRow>(
    'SELECT kid,private_pkcs8,public_spki FROM platform_signing_keyring WHERE active=TRUE',
  );
  return row;
}

function importedKey(row: KeyRow) {
  if (!row.private_pkcs8) throw new Error('Active receipt signing key is unavailable.');
  return {
    kid: row.kid,
    privateKey: createPrivateKey({ key: row.private_pkcs8, format: 'der', type: 'pkcs8' }),
    publicKey: createPublicKey({ key: row.public_spki, format: 'der', type: 'spki' }),
  };
}

async function initialize(queries: Queries) {
  await lockKeyring(queries);
  let row = await activeRow(queries);
  if (!row) {
    const pair = generateKeyPairSync('ed25519');
    const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    await queries.query(
      `INSERT INTO platform_signing_keyring(kid,private_pkcs8,public_spki,active)
       VALUES($1,$2,$3,TRUE)`,
      [`portkey-${randomUUID()}`, privateDer, publicDer],
    );
    row = await activeRow(queries);
  }
  if (!row) throw new Error('Receipt signing key could not be initialized.');
  return importedKey(row);
}

export async function signingKey(database: Database | Queries) {
  if ('transaction' in database) return database.transaction(initialize);
  return initialize(database);
}

export async function rotateSigningKey(database: Database) {
  return database.transaction(async (tx) => {
    await lockKeyring(tx);
    const [active] = await tx.query<{ recently_activated: boolean }>(
      `SELECT created_at>clock_timestamp()-($1 * interval '1 second') AS recently_activated
       FROM platform_signing_keyring WHERE active=TRUE`,
      [rotationCooldownSeconds],
    );
    if (active?.recently_activated)
      throw new Error('Signing key was rotated recently; wait 60 seconds before rotating again.');
    const [live] = await tx.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM platform_signing_keyring
       WHERE active=TRUE OR verify_until>clock_timestamp()`,
    );
    if (live.count >= keyLimit)
      throw new Error('Signing key rotation is at capacity; wait for an old verification key to expire.');
    const pair = generateKeyPairSync('ed25519');
    const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    await tx.query(
      `UPDATE platform_signing_keyring SET active=FALSE,private_pkcs8=NULL,
       verify_until=clock_timestamp()+interval '10 minutes' WHERE active=TRUE`,
    );
    const kid = `portkey-${randomUUID()}`;
    await tx.query(
      `INSERT INTO platform_signing_keyring(kid,private_pkcs8,public_spki,active)
       VALUES($1,$2,$3,TRUE)`,
      [kid, privateDer, publicDer],
    );
    return kid;
  });
}

function publicJwk(row: KeyRow) {
  const jwk = createPublicKey({ key: row.public_spki, format: 'der', type: 'spki' }).export({ format: 'jwk' });
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: row.kid, use: 'sig', alg: 'Ed25519' };
}

export async function publicJwks(database: Database) {
  return database.transaction(async (tx) => {
    await initialize(tx);
    const rows = await tx.query<KeyRow>(
      `SELECT kid,private_pkcs8,public_spki FROM platform_signing_keyring
       WHERE active=TRUE OR verify_until>clock_timestamp() ORDER BY active DESC,created_at DESC LIMIT 8`,
    );
    return { keys: rows.map(publicJwk) };
  });
}

export async function issueReceipt(database: Database, claims: Record<string, unknown>) {
  return database.transaction(async (tx) => {
    const key = await signingKey(tx);
    return signCompactJws(key.kid, key.privateKey, claims);
  });
}

export function signCompactJws(kid: string, privateKey: import('node:crypto').KeyObject, claims: Record<string, unknown>) {
  const header = b64(Buffer.from(JSON.stringify({ alg: 'Ed25519', typ: 'portkey-verification+jwt', kid })));
  const payload = b64(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), privateKey).toString('base64url')}`;
}

export { sha as pkceS256 };
