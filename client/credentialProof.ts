import {
  credentialFile,
  credentialProofInput,
  type CredentialFile,
  type CredentialProofPayload,
  type CredentialRule,
} from '../shared/credentials.js';

export function readCredential(text: string): CredentialFile {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('That file is not JSON. Choose the credential file your institution gave you.');
  }
  const parsed = credentialFile.safeParse(value);
  if (!parsed.success) throw new Error('That file is not a valid Portkey credential.');
  return parsed.data;
}

export function credentialMatches(credential: CredentialFile, rule: CredentialRule) {
  if (credential.issuer.ax !== rule.issuer.ax || credential.issuer.ay !== rule.issuer.ay) {
    throw new Error('This credential was issued by a different institution than this room accepts.');
  }
  if (credential.attributes.dept !== rule.dept || credential.attributes.year !== rule.year) {
    throw new Error('This credential does not match the room’s department and class year.');
  }
}

// The proof is generated in this browser. The credential's secret and the
// issuer signature are private circuit inputs; only the proof and its public
// signals (nullifier, issuer key, requirement, scope) reach the server.
export async function proveCredential(
  credential: CredentialFile,
  roomId: string,
  challenge: string,
): Promise<CredentialProofPayload> {
  const snarkjs = await import('snarkjs');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    credentialProofInput(credential, roomId, challenge),
    '/zk/credential.wasm',
    '/zk/credential.zkey',
  );
  return { proof, publicSignals } as CredentialProofPayload;
}
