// Institution-side, one-pass worker. Run on a schedule with a read-only metadata
// DB account and private issuer material outside the web application container.
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { deliverRevocations } from './revocationWorkerLib.js';
import { openDatabase } from '../server/database.js';
import { credentialFile, type CredentialFile } from '../shared/credentials.js';
import { type IssuerKeyFile } from './issuerLib.js';
const { DATABASE_URL, ISSUER_KEY_PATH, REVOKED_CREDENTIALS_DIR, REVOCATION_API_URL } = process.env;
if (!DATABASE_URL || !ISSUER_KEY_PATH || !REVOKED_CREDENTIALS_DIR || !REVOCATION_API_URL) throw new Error('Set DATABASE_URL, ISSUER_KEY_PATH, REVOKED_CREDENTIALS_DIR and REVOCATION_API_URL.');
if (new URL(REVOCATION_API_URL).protocol !== 'https:' && process.env.ALLOW_LOCAL_REVOCATION_TEST !== 'true') throw new Error('Issuer delivery requires HTTPS.');
const issuer = JSON.parse(await readFile(ISSUER_KEY_PATH, 'utf8')) as IssuerKeyFile;
const database = await openDatabase({ url: DATABASE_URL });
try {
  const credentials: CredentialFile[] = [];
  for (const name of await readdir(REVOKED_CREDENTIALS_DIR)) {
    if (!name.endsWith('.json')) continue;
    const text = await readFile(join(REVOKED_CREDENTIALS_DIR, name), 'utf8');
    if (text.length > 16384) throw new Error('A revoked credential file exceeds the allowed size.');
    credentials.push(credentialFile.parse(JSON.parse(text)));
  }
  const result = await deliverRevocations(database, issuer, credentials, async body => {
    const response = await fetch(new URL('/api/issuer/revocations', REVOCATION_API_URL), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new Error(`Issuer delivery failed: HTTP ${response.status}`);
  });
  console.log(JSON.stringify(result));
} finally { await database.close(); }
