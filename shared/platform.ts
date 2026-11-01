import { createHash } from 'node:crypto';

export const platformContractDigest = (contractId: string, version: number, groupIds: string[]) =>
  createHash('sha256').update([
    'portkey:proof-contract:v1', contractId.toLowerCase(), version, 'ANY',
    'semaphore-membership-v1', 'semaphore-v4', 10,
    ...[...new Set(groupIds.map(id => id.toLowerCase()))].sort(),
  ].join(':')).digest('hex');

export const GROTH16_ADAPTER = 'groth16-bn254-v1' as const;
export const BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface Groth16AdapterConfig {
  protocol: 'groth16';
  curve: 'bn128';
  nPublic: number;
  verificationKey: Record<string, unknown>;
  publicSignalNames: string[];
  fingerprint: string;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
}

export function customContractDigest(contractId: string, version: number, config: Groth16AdapterConfig) {
  return createHash('sha256').update([
    'portkey:proof-contract:v1', contractId.toLowerCase(), version, 'ANY', GROTH16_ADAPTER,
    config.fingerprint, canonicalJson(config.publicSignalNames),
  ].join(':')).digest('hex');
}

export function canonicalOrigin(value: string, allowLocalHttp: boolean) {
  const url = new URL(value);
  if (!['https:', ...(allowLocalHttp ? ['http:'] : [])].includes(url.protocol) || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash || url.origin !== value)
    throw new Error('Use an exact HTTPS origin with no path, query, or fragment.');
  return url.origin;
}
