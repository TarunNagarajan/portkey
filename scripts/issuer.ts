// Development issuer CLI.
//
//   npx tsx scripts/issuer.ts keygen
//   npx tsx scripts/issuer.ts issue --dept CSE --year 2026 --out credentials/alice.json
//   npx tsx scripts/issuer.ts verify --credential credentials/alice.json
//
// The key produced here is a demo institution key: it is committed so the app,
// tests and the course demo work out of the box, which also means anyone with
// the repository can mint credentials for the demo issuer. Replace it with an
// institution-held key (and set ISSUER_PUBLIC_KEY) for any real use.
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CREDENTIAL_VERSION,
  credentialFile,
  credentialNullifier, roomScope,
  departmentLabel,
  departments,
  MAX_CREDENTIAL_YEAR,
  MIN_CREDENTIAL_YEAR,
} from '../shared/credentials.js';
import {
  checkCredential,
  commitmentOf,
  generateIssuer,
  signRevocation,
  issueCredential,
  type IssuerKeyFile,
} from './issuerLib.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const defaultKeyPath = resolve(root, 'fixtures/dev-issuer.json');
const defaultPublicPath = resolve(root, 'server/zk/issuer.json');

const [command, ...rest] = process.argv.slice(2);
const flags = new Map<string, string>();
for (let index = 0; index < rest.length; index += 2) {
  const flag = rest[index];
  if (!flag?.startsWith('--')) continue;
  flags.set(flag.slice(2), rest[index + 1] ?? '');
}

function pathFlag(name: string, fallback: string) {
  const value = flags.get(name);
  return value ? resolve(root, value) : fallback;
}

async function readJson(path: string) {
  return JSON.parse(await readFile(path, 'utf8')) as unknown;
}

async function keygen() {
  const out = pathFlag('out', defaultKeyPath);
  const publicOut = pathFlag('public', defaultPublicPath);
  const issuer = generateIssuer();
  await mkdir(dirname(out), { recursive: true });
  await mkdir(dirname(publicOut), { recursive: true });
  await writeFile(out, `${JSON.stringify(issuer, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  await writeFile(
    publicOut,
    `${JSON.stringify({ version: CREDENTIAL_VERSION, ...issuer.publicKey }, null, 2)}\n`,
    { flag: 'wx' },
  );
  console.log(`issuer key written to ${out}`);
  console.log(`public key written to ${publicOut}`);
  console.log(`issuer Ax: ${issuer.publicKey.ax}`);
  console.log(`issuer Ay: ${issuer.publicKey.ay}`);
}

function departmentCode(value: string | undefined) {
  if (!value) throw new Error('Pass --dept, for example --dept CSE.');
  const byShort = departments.find(
    (entry) => entry.short.toLowerCase() === value.toLowerCase(),
  );
  if (byShort) return byShort.code;
  const numeric = Number(value);
  if (Number.isInteger(numeric) && departments.some((entry) => entry.code === numeric)) {
    return numeric;
  }
  throw new Error(`Unknown department "${value}". Try one of: ${departments.map((entry) => entry.short).join(', ')}.`);
}

async function issue() {
  const keyPath = pathFlag('key', defaultKeyPath);
  const issuer = (await readJson(keyPath)) as IssuerKeyFile;
  if (issuer.version !== CREDENTIAL_VERSION || !issuer.privateKey) {
    throw new Error(`${keyPath} is not a ${CREDENTIAL_VERSION} issuer key.`);
  }
  const dept = departmentCode(flags.get('dept'));
  const year = Number(flags.get('year') ?? new Date().getFullYear() + 4);
  if (!Number.isInteger(year) || year < MIN_CREDENTIAL_YEAR || year > MAX_CREDENTIAL_YEAR) {
    throw new Error(`Pass --year between ${MIN_CREDENTIAL_YEAR} and ${MAX_CREDENTIAL_YEAR}.`);
  }
  const credential = issueCredential(issuer, { dept, year }, flags.has('expires') ? Math.floor(new Date(flags.get('expires')!).getTime() / 1000) : undefined);
  const short = departments.find((entry) => entry.code === dept)?.short ?? 'DEPT';
  const out = pathFlag('out', resolve(root, 'credentials', `credential-${short}-${year}.json`));
  await mkdir(dirname(out), { recursive: true, mode: 0o700 });
  await writeFile(out, `${JSON.stringify(credentialFile.parse(credential), null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  console.log(`credential written to ${out}`);
  console.log(`attributes: ${departmentLabel(dept)}, class of ${year}`);
  console.log(`commitment: ${commitmentOf(credential)}`);
  console.log('The file is the holder\'s private credential. Do not publish it.');
}

async function verify() {
  const path = pathFlag('credential', '');
  if (!path) throw new Error('Pass --credential <file>.');
  const credential = credentialFile.parse(await readJson(path));
  const valid = checkCredential(credential) && credential.validUntil > Math.floor(Date.now() / 1000);
  console.log(valid ? 'signature and attributes verify' : 'INVALID credential signature');
  if (!valid) process.exitCode = 1;
}

async function main() {
  if (command === 'keygen') return keygen();
  if (command === 'issue') return issue();
  if (command === 'verify') return verify();
  if (command === 'revoke') {
    const holder = credentialFile.parse(await readJson(pathFlag('credential', '')));
    const roomId = flags.get('room');
    if (!roomId || !/^[a-f0-9-]{36}$/i.test(roomId)) throw new Error('Pass --room <uuid>.');
    const issuer = await readJson(pathFlag('key', defaultKeyPath)) as IssuerKeyFile;
    if (issuer.publicKey.ax !== holder.issuer.ax || issuer.publicKey.ay !== holder.issuer.ay) throw new Error('This issuer did not sign the credential.');
    const nullifier = credentialNullifier(BigInt(holder.secret), roomScope(roomId)).toString();
    const body = { roomId, nullifier, signature: signRevocation(issuer, roomId, nullifier) };
    if (flags.get('api')) {
      const response = await fetch(new URL('/api/issuer/revocations', flags.get('api')), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error(`Revocation failed: HTTP ${response.status}`);
      console.log('Credential revoked for this room.');
    } else await writeFile(pathFlag('out', resolve(root, 'revocation.json')), JSON.stringify(body, null, 2), { flag: 'wx', mode: 0o600 });
    return;
  }
  console.log('Usage:');
  console.log('  tsx scripts/issuer.ts keygen [--out fixtures/dev-issuer.json] [--public server/zk/issuer.json]');
  console.log('  tsx scripts/issuer.ts issue [--dept CSE] [--year 2026] [--out credentials/student.json]');
  console.log('  Default output: credentials/credential-<DEPT>-<YEAR>.json');
  console.log('  tsx scripts/issuer.ts verify --credential credentials/student.json');
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
