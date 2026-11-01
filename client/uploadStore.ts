import { privateDirectory, encryptDistributionChunk, type DistributionPlan } from './roomCrypto.js';
const NAME = 'portkey-upload-journal-v1';
async function db() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const open = indexedDB.open(NAME, 1);
    open.onupgradeneeded = () => { open.result.createObjectStore('plans'); open.result.createObjectStore('chunks'); };
    open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);
  });
}
async function transact<T>(store: string, mode: IDBTransactionMode, work: (objectStore: IDBObjectStore, done: (value: T) => void) => void) {
  const database = await db();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = database.transaction(store, mode); let result: T;
      work(tx.objectStore(store), value => { result = value; });
      tx.oncomplete = () => resolve(result); tx.onabort = tx.onerror = () => reject(tx.error ?? new Error('Upload storage failed.'));
    });
  } finally { database.close(); }
}
const id = (plan: DistributionPlan) => `${plan.roomId}:${plan.fileId}`;
interface StoredPlan extends Omit<DistributionPlan, 'file'> {
  sourceName: string; sourceType: string; opfsName?: string; sourceBytes?: ArrayBuffer;
}
export async function saveUpload(plan: DistributionPlan) {
  const { file, ...rest } = plan;
  const stored: StoredPlan = { ...rest, sourceName: file.name, sourceType: file.type };
  const root = await privateDirectory();
  if (root) {
    stored.opfsName = `portkey-upload-${plan.roomId}-${plan.fileId}`;
    try {
      const handle = await root.getFileHandle(stored.opfsName, { create: true });
      const writer = await handle.createWritable();
      await file.stream().pipeTo(writer);
    } catch (error) {
      await root.removeEntry(stored.opfsName).catch(() => undefined);
      throw error;
    }
  } else {
    if (file.size > 50 * 1048576) throw new Error('Durable uploads above 50 MiB require browser private file storage.');
    stored.sourceBytes = await file.arrayBuffer();
  }
  try { await transact<void>('plans', 'readwrite', (store, done) => { store.add(stored, id(plan)); done(); }); }
  catch (error) { if (root && stored.opfsName) await root.removeEntry(stored.opfsName).catch(() => undefined); throw error; }
}
export async function pendingUploads(roomId: string) {
  const all = await transact<StoredPlan[]>('plans', 'readonly', (store, done) => { const r = store.getAll(); r.onsuccess = () => done(r.result); });
  return Promise.all(all.filter(plan => plan.roomId === roomId).map(async stored => {
    let source: BlobPart = stored.sourceBytes ?? new ArrayBuffer(0);
    let sourceMissing = false;
    if (stored.opfsName) {
      const root = await privateDirectory();
      try { if (!root) throw new Error('Private storage unavailable.'); source = await (await root.getFileHandle(stored.opfsName)).getFile(); }
      catch { sourceMissing = true; }
    }
    return { ...stored, sourceMissing, file: new File([source], stored.sourceName, { type: stored.sourceType }) } as DistributionPlan;
  }));
}
export async function forgetUpload(plan: DistributionPlan) {
  // Make the plan undiscoverable before deleting ciphertext reservations.
  await transact<void>('plans', 'readwrite', (store, done) => { store.delete(id(plan)); done(); });
  await transact<void>('chunks', 'readwrite', (store, done) => { store.delete(IDBKeyRange.bound(id(plan) + ':', id(plan) + ':\uffff')); done(); });
  const root = await privateDirectory();
  if (root) {
    await root.removeEntry(`portkey-upload-${plan.roomId}-${plan.fileId}`).catch(() => undefined);
  }
}
export async function immutableUploadChunk(plan: DistributionPlan, index: number) {
  const key = `${id(plan)}:${index}`;
  const prior = await transact<{ ciphertext: Uint8Array; sha256: string } | 'reserved' | undefined>('chunks', 'readwrite', (store, done) => {
    const request = store.get(key);
    request.onsuccess = () => { if (!request.result) store.add('reserved', key); done(request.result); };
  });
  if (prior === 'reserved') throw new Error('Encryption was interrupted before its ciphertext was saved. Discard this upload and choose the file again.');
  if (prior) return prior;
  // Persist the reservation before crypto, then persist immutable bytes before network I/O.
  const chunk = await encryptDistributionChunk(plan, index);
  await transact<void>('chunks', 'readwrite', (store, done) => { store.put(chunk, key); done(); });
  return chunk;
}
