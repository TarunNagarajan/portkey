import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';
import { z } from 'zod';
import {
  credentialProofPayload,
  parseField,
  roomScope,
  type CredentialRule,
} from '../shared/credentials.js';
import { config } from './config.js';
import { HttpError, requireCondition } from './errors.js';

const field = z.string().regex(/^[0-9]{1,77}$/);
const issuerKeyFile = z
  .object({ version: z.string().optional(), ax: field, ay: field })
  .strict();

// The issuer key is pinned per room when the requirement is created. Without a
// configured institution key the demo issuer committed under server/zk is used,
// so the flow works out of the box for the course prototype.
function loadIssuer() {
  if (!config.issuerPublicKey) {
    return issuerKeyFile.parse(
      JSON.parse(readFileSync(new URL('./zk/issuer.json', import.meta.url), 'utf8')),
    );
  }
  try {
    return issuerKeyFile.parse(JSON.parse(config.issuerPublicKey));
  } catch {
    throw new Error('ISSUER_PUBLIC_KEY must be JSON with decimal "ax" and "ay" fields.');
  }
}

export const issuerPublicKey = loadIssuer();
const artifactManifest = JSON.parse(readFileSync(new URL('./zk/manifest.json', import.meta.url), 'utf8'));
const files = {
  circuit: '../circuits/credential.circom', wasm: '../public/zk/credential.wasm',
  zkey: '../public/zk/credential.zkey', verificationKey: './zk/verification_key.json',
};
for (const [name, path] of Object.entries(files)) {
  const hash = createHash('sha256').update(readFileSync(new URL(path, import.meta.url))).digest('hex');
  if (artifactManifest.hashes[name] !== hash) throw new Error(`ZK artifact checksum mismatch: ${name}`);
}
if (config.production && !config.allowDemoCredentials && issuerPublicKey.ax === '11799487317923059034946923537244041186142543521718251734244989129882501158887' && issuerPublicKey.ay === '4840215600608879220452845588445209865294337713962458455607436623231169040087') {
  throw new Error('The bundled demo issuer cannot authorize production credentials.');
}
if (config.production && !config.allowDemoCredentials && artifactManifest.setup !== 'external-verified') {
  throw new Error('Production requires verified external ceremony artifacts; use ALLOW_DEMO_CREDENTIALS=true only for a demo.');
}

const verificationKey: unknown = JSON.parse(
  readFileSync(new URL('./zk/verification_key.json', import.meta.url), 'utf8'),
);

export interface VerifiedCredential {
  nullifier: string;
  challenge: string;
  validUntil: number;
}

// Verifies the zero-knowledge proof, then binds every public signal to what the
// room actually requires. SnarkJS alone would accept any well-formed proof, so
// the signal checks are as important as the pairing check.
export async function verifyCredentialProof(
  input: unknown,
  roomId: string,
  rule: CredentialRule,
): Promise<VerifiedCredential> {
  const payload = credentialProofPayload.parse(input);
  let valid = false;
  try {
    valid = await snarkjs.groth16.verify(verificationKey, payload.publicSignals, payload.proof);
  } catch {
    valid = false;
  }
  requireCondition(
    valid,
    422,
    'CREDENTIAL_PROOF_INVALID',
    'That credential proof did not verify.',
  );

  let signals: bigint[];
  try {
    signals = payload.publicSignals.map(parseField);
  } catch {
    throw new HttpError(422, 'CREDENTIAL_PROOF_INVALID', 'That credential proof did not verify.');
  }
  const [nullifier, _binding, ax, ay, dept, year, scope, challenge, validUntil] = signals;
  requireCondition(
    ax === BigInt(rule.issuer.ax) && ay === BigInt(rule.issuer.ay),
    422,
    'CREDENTIAL_ISSUER_MISMATCH',
    'That credential was issued by a different institution than this room accepts.',
  );
  requireCondition(
    dept === BigInt(rule.dept) && year === BigInt(rule.year),
    422,
    'CREDENTIAL_MISMATCH',
    'That credential does not match this room’s requirement.',
  );
  requireCondition(
    scope === roomScope(roomId),
    422,
    'CREDENTIAL_PROOF_INVALID',
    'That proof was made for a different room.',
  );
  return { nullifier: nullifier.toString(), challenge: challenge.toString(), validUntil: Number(validUntil) };
}

export function credentialIssuer() {
  return { ax: issuerPublicKey.ax, ay: issuerPublicKey.ay };
}
