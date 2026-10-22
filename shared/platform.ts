import { createHash } from 'node:crypto';

export const platformContractDigest = (contractId: string, version: number, groupIds: string[]) =>
  createHash('sha256').update([
    'portkey:proof-contract:v1', contractId.toLowerCase(), version, 'ANY',
    'semaphore-membership-v1', 'semaphore-v4', 10,
    ...[...new Set(groupIds.map(id => id.toLowerCase()))].sort(),
  ].join(':')).digest('hex');

export function canonicalOrigin(value: string, allowLocalHttp: boolean) {
  const url = new URL(value);
  if (!['https:', ...(allowLocalHttp ? ['http:'] : [])].includes(url.protocol) || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash || url.origin !== value)
    throw new Error('Use an exact HTTPS origin with no path, query, or fragment.');
  return url.origin;
}
