// Issuer-side credential minting. This is development tooling: the institution
// that grants eligibility runs these helpers and hands each holder their own
// credential file. The credential contains no name, roll number, or email.
import { poseidon3 } from 'poseidon-lite/poseidon3';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import type { Signature } from '@zk-kit/eddsa-poseidon';

// The package's ESM build imports named exports from the CommonJS `blakejs`
// package, which Node's ESM loader cannot synthesize, and its `/blake-1`
// subpath points at a file that is not shipped. The CommonJS build works, so
// load that explicitly.
const require = createRequire(import.meta.url);
const eddsa = require('@zk-kit/eddsa-poseidon') as {
  EdDSAPoseidon: new (privateKey: Buffer | Uint8Array | string) => {
    publicKey: [bigint, bigint];
  };
  signMessage: (privateKey: Buffer | Uint8Array | string, message: bigint) => Signature<bigint>;
  verifySignature: (
    message: bigint,
    signature: Signature<bigint>,
    publicKey: [bigint, bigint],
  ) => boolean;
};
import {
  CREDENTIAL_VERSION,
  credentialCommitment,
  credentialFile,
  FIELD_PRIME,
  type CredentialFile,
  type CredentialRequirement,
} from '../shared/credentials.js';

export interface IssuerKeyFile {
  version: typeof CREDENTIAL_VERSION;
  // base64 of 32 random bytes; dev issuer only, never a real institution key
  privateKey: string;
  publicKey: { ax: string; ay: string };
}

export function generateIssuer(): IssuerKeyFile {
  const privateKey = randomBytes(32);
  const holder = new eddsa.EdDSAPoseidon(privateKey);
  return {
    version: CREDENTIAL_VERSION,
    privateKey: privateKey.toString('base64'),
    publicKey: {
      ax: holder.publicKey[0].toString(),
      ay: holder.publicKey[1].toString(),
    },
  };
}

function randomSecret() {
  for (;;) {
    const candidate = BigInt(`0x${randomBytes(31).toString('hex')}`);
    if (candidate > 0n && candidate < FIELD_PRIME) return candidate;
  }
}

export function issueCredential(
  issuer: IssuerKeyFile,
  attributes: CredentialRequirement,
  validUntil = Math.floor(Date.now() / 1000) + 365 * 24 * 3600,
): CredentialFile {
  const secret = randomSecret();
  const commitment = credentialCommitment(secret, attributes.dept, attributes.year, validUntil);
  const signature = eddsa.signMessage(Buffer.from(issuer.privateKey, 'base64'), commitment);
  return {
    version: CREDENTIAL_VERSION,
    issuer: issuer.publicKey,
    attributes,
    validUntil,
    secret: secret.toString(),
    signature: {
      R8x: signature.R8[0].toString(),
      R8y: signature.R8[1].toString(),
      S: signature.S.toString(),
    },
  };
}

export function checkCredential(credential: CredentialFile) {
  const commitment = credentialCommitment(
    BigInt(credential.secret),
    credential.attributes.dept,
    credential.attributes.year,
    credential.validUntil,
  );
  return eddsa.verifySignature(
    commitment,
    { R8: [BigInt(credential.signature.R8x), BigInt(credential.signature.R8y)], S: BigInt(credential.signature.S) },
    [BigInt(credential.issuer.ax), BigInt(credential.issuer.ay)],
  );
}

export function commitmentOf(credential: CredentialFile) {
  return credentialCommitment(
    BigInt(credential.secret),
    credential.attributes.dept,
    credential.attributes.year,
    credential.validUntil,
  );
}

export { credentialFile };

export function revocationMessage(roomId: string, nullifier: string) {
  return poseidon3([BigInt(`0x${roomId.replaceAll('-', '')}`), BigInt(nullifier), 20261101n]);
}
export function signRevocation(issuer: IssuerKeyFile, roomId: string, nullifier: string) {
  const signature = eddsa.signMessage(Buffer.from(issuer.privateKey, 'base64'), revocationMessage(roomId, nullifier));
  return { R8x: signature.R8[0].toString(), R8y: signature.R8[1].toString(), S: signature.S.toString() };
}
export function verifyRevocation(issuer: { ax: string; ay: string }, roomId: string, nullifier: string, signature: { R8x: string; R8y: string; S: string }) {
  try { return eddsa.verifySignature(revocationMessage(roomId, nullifier), {
    R8: [BigInt(signature.R8x), BigInt(signature.R8y)], S: BigInt(signature.S),
  }, [BigInt(issuer.ax), BigInt(issuer.ay)]); } catch { return false; }
}
