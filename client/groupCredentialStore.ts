import { Identity } from '@semaphore-protocol/identity';

const DATABASE = 'portkey-reusable-credentials';
const STORE = 'credentials';
const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface GroupCredential {
  id: string;
  groupId: string;
  name: string;
  description: string;
  commitment: string;
  privateKey: string;
  pending: boolean;
}

interface CredentialRecord {
  version: 1;
  groupId: string;
  privateKey: string;
  commitment: string;
  name?: string;
  description?: string;
}

function database(): Promise<IDBDatabase> {
  if (!('indexedDB' in window)) {
    return Promise.reject(new Error('This browser cannot save credentials. Enable site storage or use a current browser.'));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'groupId' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Could not open local credential storage. Check browser site storage settings.'));
    request.onblocked = () => reject(new Error('Local credential storage is busy in another tab. Close other Portkey tabs and retry.'));
  });
}

function canonicalGroupId(value: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error('The credential group address is invalid.');
  }
  return value.toLowerCase();
}

function validate(value: unknown, groupId: string): GroupCredential {
  groupId = canonicalGroupId(groupId);
  if (!value || typeof value !== 'object') {
    throw new Error('This saved credential is damaged. It cannot be recovered from the server.');
  }
  const record = value as Partial<CredentialRecord>;
  if (
    record.version !== 1
    || record.groupId !== groupId
    || typeof record.privateKey !== 'string'
    || typeof record.commitment !== 'string'
    || !/^[1-9][0-9]{0,76}$/.test(record.commitment)
    || BigInt(record.commitment) >= SCALAR_FIELD
    || (record.name !== undefined && typeof record.name !== 'string')
    || (record.description !== undefined && typeof record.description !== 'string')
  ) {
    throw new Error('This saved credential is damaged. It cannot be recovered from the server.');
  }
  try {
    const identity = Identity.import(record.privateKey);
    if (identity.commitment.toString() !== record.commitment) throw new Error('credential mismatch');
  } catch {
    throw new Error('This saved credential is damaged. It cannot be recovered from the server.');
  }
  return {
    id: groupId,
    groupId,
    name: record.name ?? '',
    description: record.description ?? '',
    commitment: record.commitment,
    privateKey: record.privateKey,
    pending: record.name === undefined,
  };
}

export async function loadGroupCredentials(): Promise<GroupCredential[]> {
  return (await loadGroupCredentialState()).credentials;
}

export async function loadGroupCredentialState(): Promise<{
  credentials: GroupCredential[];
  damaged: Array<{ groupId: string; error: string }>;
}> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const request = tx.objectStore(STORE).getAll();
      const values: GroupCredential[] = [];
      const damaged: Array<{ groupId: string; error: string }> = [];
      request.onsuccess = () => {
        const records = request.result as CredentialRecord[];
        const byGroup = new Map<string, CredentialRecord[]>();
        for (const record of records) {
          try {
            const id = canonicalGroupId(record.groupId);
            byGroup.set(id, [...(byGroup.get(id) ?? []), record]);
          } catch {
            if (typeof record?.groupId === 'string') {
            damaged.push({
              groupId: record.groupId,
              error: 'This saved credential has an invalid group address. It cannot be recovered from the server.',
            });
            }
          }
        }
        for (const [groupId, matches] of byGroup) {
          if (matches.length > 1) {
            damaged.push({
              groupId,
              error: 'More than one saved record refers to this group. Reset this selected group credential before using it.',
            });
            continue;
          }
          try {
            values.push(validate(matches[0], groupId));
          } catch (error) {
            damaged.push({ groupId, error: error instanceof Error ? error.message : 'This saved credential is damaged.' });
          }
        }
      };
      tx.oncomplete = () => resolve({ credentials: values, damaged });
      tx.onerror = () => reject(new Error('Could not read saved credentials.'));
      tx.onabort = () => reject(new Error('Could not read saved credentials.'));
    });
  } finally {
    db.close();
  }
}

export async function loadOrCreateGroupCredential(groupId: string): Promise<GroupCredential> {
  groupId = canonicalGroupId(groupId);
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      const request = store.get(groupId);
      let result: GroupCredential | null = null;
      let failure: Error | null = null;
      request.onsuccess = () => {
        try {
          const existing = request.result as CredentialRecord | undefined;
          if (existing !== undefined) {
            result = validate(existing, groupId);
          } else {
            const identity = new Identity();
            const record: CredentialRecord = {
              version: 1,
              groupId,
              privateKey: identity.export(),
              commitment: identity.commitment.toString(),
            };
            store.add(record);
            result = validate(record, groupId);
          }
        } catch (error) {
          failure = error instanceof Error ? error : new Error('Could not save this credential.');
          tx.abort();
        }
      };
      tx.oncomplete = () => {
        if (result) resolve(result);
        else reject(failure ?? new Error('Could not save this credential.'));
      };
      tx.onerror = () => reject(failure ?? new Error('Could not save this credential.'));
      tx.onabort = () => reject(failure ?? new Error('Could not save this credential.'));
    });
  } finally {
    db.close();
  }
}

export async function confirmGroupCredential(groupId: string, name: string, description: string): Promise<void> {
  groupId = canonicalGroupId(groupId);
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      const request = store.get(groupId);
      request.onsuccess = () => {
        try {
          if (request.result === undefined) throw new Error('The saved credential is missing. Retry enrollment from this browser.');
          const record = validate(request.result, groupId);
          store.put({ version: 1, groupId, privateKey: record.privateKey, commitment: record.commitment, name, description } satisfies CredentialRecord);
        } catch (error) { reject(error instanceof Error ? error : new Error('Could not update the local credential.')); tx.abort(); }
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('Could not update the local credential.'));
      tx.onabort = () => reject(new Error('Could not update the local credential.'));
    });
  } finally { db.close(); }
}

export async function forgetGroupCredential(groupId: string): Promise<void> {
  groupId = canonicalGroupId(groupId);
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      const request = store.getAll();
      request.onsuccess = () => {
        for (const record of request.result as CredentialRecord[]) {
          try { if (canonicalGroupId(record.groupId) === groupId) store.delete(record.groupId); }
          catch { /* Invalid keys cannot correspond to a valid group identifier. */ }
        }
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('Could not forget this credential.'));
      tx.onabort = () => reject(new Error('Could not forget this credential.'));
    });
  } finally { db.close(); }
}

export async function forgetDamagedGroupCredential(groupId: string): Promise<void> {
  let canonicalId: string | null = null;
  try {
    canonicalId = canonicalGroupId(groupId);
  } catch {
    if (!groupId || groupId.length > 120) throw new Error('The damaged credential storage key is invalid.');
  }

  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      if (!canonicalId) {
        store.delete(groupId);
      } else {
        const request = store.getAll();
        request.onsuccess = () => {
          for (const record of request.result as CredentialRecord[]) {
            try {
              if (canonicalGroupId(record.groupId) === canonicalId) store.delete(record.groupId);
            } catch {
              // Leave unrelated damaged entries available for selective repair.
            }
          }
        };
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error('Could not reset this damaged credential.'));
      tx.onabort = () => reject(new Error('Could not reset this damaged credential.'));
    });
  } finally {
    db.close();
  }
}
