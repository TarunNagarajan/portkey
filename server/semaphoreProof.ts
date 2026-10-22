import { verifyProof, type SemaphoreProof } from '@semaphore-protocol/proof';
import { z } from 'zod';
import { HttpError } from './errors.js';

export const PROOF_DEPTH = 10;
const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const decimalPattern = /^(0|[1-9][0-9]{0,76})$/;
const decimal = z.string().max(77).regex(decimalPattern);
const field = decimal.refine(value => decimalPattern.test(value) && BigInt(value) < SCALAR_FIELD);
const point = decimal.refine(value => decimalPattern.test(value) && BigInt(value) < BASE_FIELD);
export const semaphoreProofSchema = z.object({
  merkleTreeDepth: z.literal(PROOF_DEPTH), merkleTreeRoot: field, message: field,
  nullifier: field, scope: field,
  points: z.tuple([point, point, point, point, point, point, point, point]),
}).strict();

let activeVerifications = 0;
export async function verifySemaphoreProofBounded(proof: SemaphoreProof) {
  if (activeVerifications >= 1)
    throw new HttpError(429, 'PROOF_BUSY', 'Proof checks are busy. Wait a moment and try again.');
  activeVerifications += 1;
  try { return await verifyProof(proof); }
  finally { activeVerifications -= 1; }
}
