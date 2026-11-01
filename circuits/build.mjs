// Compiles the credential circuit and produces the Groth16 proving artifacts.
//
// Artifacts under public/zk are served to the browser and the verification key
// is read by the API, so both are committed. The intermediate build directory
// (pot file, r1cs, zkey drafts) is ignored.
//
// The development powers-of-tau ceremony is generated locally and is NOT a
// production trusted setup: anyone holding the entropy could forge proofs.
// Replacing it with a public multi-party ceremony is required before relying on
// these proofs outside the course prototype.
import { execFileSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const build = join(root, 'circuits', 'build');
const circuit = join(root, 'circuits', 'credential.circom');
const r1cs = join(build, 'credential.r1cs');
const wasm = join(build, 'credential_js', 'credential.wasm');
const ptau = process.env.ZK_PTAU ? resolve(process.env.ZK_PTAU) : join(build, 'pot14_final.ptau');
const zkey = join(build, 'credential.zkey');
const vkey = join(build, 'verification_key.json');
const clientDir = join(root, 'public', 'zk');
const serverDir = join(root, 'server', 'zk');

const library = join(root, 'node_modules', 'circomlib', 'circuits');

function snarkjs(...args) {
  execFileSync('npx', ['--no-install', 'snarkjs', ...args], { cwd: root, stdio: 'inherit' });
}

function log(message) {
  console.log(`[zk] ${message}`);
}

mkdirSync(build, { recursive: true });
mkdirSync(clientDir, { recursive: true });
mkdirSync(serverDir, { recursive: true });

log('compiling credential.circom');
execFileSync(
  'npx',
  ['--no-install', 'circom2', circuit, '--r1cs', '--wasm', '-l', library, '-o', build],
  { cwd: root, stdio: 'inherit' },
);

if (!existsSync(ptau)) {
  log('generating development powers of tau (2^14)');
  const draft = join(build, 'pot14_0000.ptau');
  const contributed = join(build, 'pot14_0001.ptau');
  snarkjs('powersoftau', 'new', 'bn128', '14', draft, '-v');
  snarkjs(
    'powersoftau',
    'contribute',
    draft,
    contributed,
    '--name=portkey-dev',
    `-e=${randomBytes(32).toString('hex')}`,
    '-v',
  );
  snarkjs('powersoftau', 'prepare', 'phase2', contributed, ptau, '-v');
}

if (process.env.ZK_FINAL_ZKEY) {
  if (!process.env.ZK_PTAU || !process.env.ZK_CEREMONY_URL?.startsWith('https://')) throw new Error('External setup requires ZK_PTAU and HTTPS ZK_CEREMONY_URL provenance.');
  snarkjs('powersoftau', 'verify', ptau);
  snarkjs('zkey', 'verify', r1cs, ptau, resolve(process.env.ZK_FINAL_ZKEY));
  copyFileSync(resolve(process.env.ZK_FINAL_ZKEY), zkey);
} else {
log('running Groth16 setup');
const initialZkey = join(build, 'credential_0000.zkey');
snarkjs('groth16', 'setup', r1cs, ptau, initialZkey);
snarkjs(
  'zkey',
  'contribute',
  initialZkey,
  zkey,
  '--name=portkey-dev',
  `-e=${randomBytes(32).toString('hex')}`,
);

}
snarkjs('zkey', 'export', 'verificationkey', zkey, vkey);

copyFileSync(wasm, join(clientDir, 'credential.wasm'));
copyFileSync(zkey, join(clientDir, 'credential.zkey'));
copyFileSync(vkey, join(serverDir, 'verification_key.json'));

const kb = (path) => `${Math.round(statSync(path).size / 1024)} KiB`;
log(`prover wasm  ${kb(join(clientDir, 'credential.wasm'))}`);
log(`prover zkey  ${kb(join(clientDir, 'credential.zkey'))}`);
log(`verifier key ${kb(join(serverDir, 'verification_key.json'))}`);
log('done');

const sha256 = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const manifest = {
  protocol: 'portkey-credential-v2',
  setup: process.env.ZK_FINAL_ZKEY ? 'external-verified' : 'development',
  ceremony: process.env.ZK_CEREMONY_URL ?? null,
  generatedAt: new Date().toISOString(),
  hashes: { circuit: sha256(circuit), wasm: sha256(wasm), zkey: sha256(zkey), verificationKey: sha256(vkey), ptau: sha256(ptau) },
};
for (const dir of [clientDir, serverDir]) writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
