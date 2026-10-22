import { Identity } from '@semaphore-protocol/identity';

const DATABASE = 'portkey-workshop-credentials';
const STORE = 'identities';

interface IdentityRecord {
  version: 1;
  roomId: string;
  privateKey: string;
  commitment: string;
}

export interface WorkshopIdentity {
  identity: Identity;
  exportedIdentity: string;
  commitment: string;
}

function openDatabase(): Promise<IDBDatabase> {
  if (!('indexedDB' in window))
    return Promise.reject(new Error('This browser cannot save a workshop credential. Use a current browser with site storage enabled.'));
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE))
        request.result.createObjectStore(STORE, { keyPath: 'roomId' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Could not open browser storage for the workshop credential. Check site storage settings and retry.'));
    request.onblocked = () => reject(new Error('Browser storage is busy in another tab. Close other workshop tabs and retry.'));
  });
}

function validateRecord(value: unknown, roomId: string): WorkshopIdentity {
  if (!value || typeof value !== 'object') throw new Error('The saved workshop credential is damaged. This browser has no recovery copy.');
  const record = value as Partial<IdentityRecord>;
  if (record.version !== 1 || record.roomId !== roomId || typeof record.privateKey !== 'string' ||
      typeof record.commitment !== 'string' || !/^[1-9][0-9]{0,76}$/.test(record.commitment))
    throw new Error('The saved workshop credential is damaged. This browser has no recovery copy.');
  try {
    const identity = Identity.import(record.privateKey);
    const exportedIdentity = identity.export();
    if (identity.commitment.toString() !== record.commitment)
      throw new Error('credential commitment mismatch');
    return { identity, exportedIdentity, commitment: record.commitment };
  } catch {
    throw new Error('The saved workshop credential is damaged. This browser has no recovery copy.');
  }
}

export async function loadWorkshopIdentity(roomId: string): Promise<WorkshopIdentity | null> {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE, 'readonly');
      const request = transaction.objectStore(STORE).get(roomId);
      let result: WorkshopIdentity | null = null;
      let failure: Error | null = null;
      request.onsuccess = () => {
        if (request.result !== undefined) {
          try { result = validateRecord(request.result, roomId); }
          catch (error) { failure = error instanceof Error ? error : new Error('Could not read the saved workshop credential.'); }
        }
      };
      transaction.oncomplete = () => failure ? reject(failure) : resolve(result);
      transaction.onerror = () => reject(new Error('Could not read the saved workshop credential.'));
      transaction.onabort = () => reject(failure ?? new Error('Could not read the saved workshop credential.'));
    });
  } finally {
    database.close();
  }
}

export async function resetWorkshopIdentity(roomId: string): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE, 'readwrite');
      transaction.objectStore(STORE).delete(roomId);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error('Could not reset this workshop credential.'));
      transaction.onabort = () => reject(new Error('Could not reset this workshop credential.'));
    });
  } finally {
    database.close();
  }
}

export async function getOrCreateWorkshopIdentity(roomId: string): Promise<WorkshopIdentity> {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE, 'readwrite');
      const store = transaction.objectStore(STORE);
      const request = store.get(roomId);
      let result: WorkshopIdentity | null = null;
      let failure: Error | null = null;
      request.onsuccess = () => {
        try {
          if (request.result !== undefined) {
            result = validateRecord(request.result, roomId);
          } else {
            const identity = new Identity();
            const record: IdentityRecord = {
              version: 1,
              roomId,
              privateKey: identity.export(),
              commitment: identity.commitment.toString(),
            };
            store.add(record);
            result = { identity, exportedIdentity: record.privateKey, commitment: record.commitment };
          }
        } catch (error) {
          failure = error instanceof Error ? error : new Error('Could not save the workshop credential.');
          transaction.abort();
        }
      };
      transaction.oncomplete = () => result ? resolve(result) : reject(failure ?? new Error('Could not save the workshop credential.'));
      transaction.onerror = () => reject(failure ?? new Error('Could not save the workshop credential.'));
      transaction.onabort = () => reject(failure ?? new Error('Could not save the workshop credential.'));
    });
  } finally {
    database.close();
  }
}
