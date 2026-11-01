import { z } from 'zod';
// Import the two widths we use rather than the barrel, which pulls every round
// constant into the browser bundle.
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { poseidon4 } from 'poseidon-lite/poseidon4';

// A credential is a set of non-identifying attributes signed by an issuer. The
// holder proves possession of that signature and that the attributes match a
// room's requirement, without revealing the secret or the signature.
export const CREDENTIAL_VERSION = 'portkey-credential-v2';
export const MIN_CREDENTIAL_YEAR = 2000;
export const MAX_CREDENTIAL_YEAR = 2100;
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const departments = [
  { code: 1, short: 'CSE', label: 'Computer Science (CSE)' },
  { code: 2, short: 'ISE', label: 'Information Science (ISE)' },
  { code: 3, short: 'ECE', label: 'Electronics (ECE)' },
  { code: 4, short: 'EEE', label: 'Electrical (EEE)' },
  { code: 5, short: 'ME', label: 'Mechanical (ME)' },
  { code: 6, short: 'CV', label: 'Civil (CV)' },
  { code: 7, short: 'BT', label: 'Biotechnology (BT)' },
  { code: 8, short: 'AIML', label: 'AI & Machine Learning (AIML)' },
  { code: 9, short: 'DS', label: 'Data Science (DS)' },
  { code: 10, short: 'OTHER', label: 'Other department' },
] as const;

export function departmentLabel(code: number) {
  return departments.find((entry) => entry.code === code)?.label ?? 'Unknown department';
}

const fieldValue = z.string().regex(/^[0-9]{1,77}$/, 'Expected a decimal field element.');
const positiveField = z.string().regex(/^[1-9][0-9]{0,76}$/, 'Expected a positive decimal value.');

export const credentialRequirement = z
  .object({
    dept: z.number().int().min(1).max(departments.length),
    year: z.number().int().min(MIN_CREDENTIAL_YEAR).max(MAX_CREDENTIAL_YEAR),
  })
  .strict();

export const credentialFile = z
  .object({
    version: z.literal(CREDENTIAL_VERSION),
    issuer: z.object({ ax: fieldValue, ay: fieldValue }).strict(),
    attributes: credentialRequirement,
    validUntil: z.number().int().min(1).max(4294967295),
    // The secret never leaves the holder's browser; the server only ever sees
    // the proof and its nullifier.
    secret: positiveField,
    signature: z.object({ R8x: fieldValue, R8y: fieldValue, S: positiveField }).strict(),
  })
  .strict();

export const credentialProofPayload = z
  .object({
    proof: z
      .object({
        pi_a: z.array(fieldValue).length(3),
        pi_b: z.array(z.array(fieldValue).length(2)).length(3),
        pi_c: z.array(fieldValue).length(3),
        protocol: z.literal('groth16'),
        curve: z.literal('bn128'),
      })
      .strict(),
    // [nullifier, binding, issuerAx, issuerAy, dept, year, scope, challenge, validUntil]
    publicSignals: z.array(fieldValue).length(9),
  })
  .strict();

export type CredentialRequirement = z.infer<typeof credentialRequirement>;
export type CredentialFile = z.infer<typeof credentialFile>;
export type CredentialProofPayload = z.infer<typeof credentialProofPayload>;

export interface CredentialRule extends CredentialRequirement {
  issuer: { ax: string; ay: string };
}

export function parseField(value: string) {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FIELD_PRIME) throw new Error('Field element out of range.');
  return parsed;
}

// One room, one scope. A credential's nullifier is stable inside a room and
// unlinkable to its nullifier in any other room.
export function roomScope(roomId: string) {
  return BigInt(`0x${roomId.replaceAll('-', '')}`);
}

export function credentialCommitment(secret: bigint, dept: number, year: number, validUntil: number) {
  return poseidon4([secret, BigInt(dept), BigInt(year), BigInt(validUntil)]);
}

export function credentialNullifier(secret: bigint, scope: bigint) {
  return poseidon2([secret, scope]);
}

// Circuit inputs. The server only receives the resulting proof and public
// signals, never the secret or the signature.
export function credentialProofInput(credential: CredentialFile, roomId: string, challenge: string) {
  return {
    challenge,
    validUntil: credential.validUntil,
    issuerAx: credential.issuer.ax,
    issuerAy: credential.issuer.ay,
    dept: credential.attributes.dept,
    year: credential.attributes.year,
    scope: roomScope(roomId).toString(),
    secret: credential.secret,
    sigR8x: credential.signature.R8x,
    sigR8y: credential.signature.R8y,
    sigS: credential.signature.S,
  };
}
