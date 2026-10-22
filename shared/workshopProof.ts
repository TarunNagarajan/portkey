import { keccak256, toUtf8Bytes } from 'ethers';

export const WORKSHOP_PROOF_VERSION = 'semaphore-v4';
export const WORKSHOP_PROOF_DEPTH = 10;
export const WORKSHOP_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const WORKSHOP_BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function protocolValue(value: string) {
  return (BigInt(keccak256(toUtf8Bytes(value))) >> 8n).toString();
}

export function workshopScope(roomId: string) {
  return protocolValue(`portkey:workshop-admission:v1:${roomId}`);
}

export function workshopMessage(input: {
  challengeId: string;
  nonce: string;
  roomId: string;
  sessionId: string;
  root: string;
  policyDigest?: string | null;
}) {
  if (input.policyDigest) {
    return protocolValue([
      'portkey:reusable-proof-challenge:v1',
      input.policyDigest,
      input.challengeId,
      input.nonce,
      input.roomId,
      input.sessionId,
      input.root,
      WORKSHOP_PROOF_VERSION,
      WORKSHOP_PROOF_DEPTH,
    ].join(':'));
  }
  return protocolValue([
    'portkey:workshop-proof-challenge:v1',
    input.challengeId,
    input.nonce,
    input.roomId,
    input.sessionId,
    input.root,
    WORKSHOP_PROOF_VERSION,
    WORKSHOP_PROOF_DEPTH,
  ].join(':'));
}

export function workshopPolicyDigest(groupIds: string[]) {
  const ids = groupIds.map(id => id.toLowerCase()).sort();
  if (ids.length < 1 || ids.length > 4 || new Set(ids).size !== ids.length)
    throw new Error('A proof rule requires one to four distinct credential groups.');
  return keccak256(toUtf8Bytes([
    'portkey:proof-policy:v1',
    'any',
    'semaphore-fixed-adapter',
    WORKSHOP_PROOF_VERSION,
    WORKSHOP_PROOF_DEPTH,
    ...ids,
  ].join(':'))).slice(2);
}
