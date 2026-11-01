import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  commitRoomFileKeyState,
  decryptRoomFileHistory,
  encryptRoomFileHistory,
  roomFileBase64,
  roomFileFingerprint,
} from '../client/roomFileCrypto.js';

test('key history is bound to room and epoch and validates every prior key fingerprint', async () => {
  const roomId = randomUUID();
  const current = new Uint8Array(randomBytes(32));
  const old = new Uint8Array(randomBytes(32));
  const oldFingerprint = await roomFileFingerprint(old);
  const history = { [oldFingerprint]: roomFileBase64(old) };
  const envelope = await encryptRoomFileHistory(roomId, 2, current, history);
  assert.deepEqual(await decryptRoomFileHistory(roomId, 2, current, envelope), history);
  await assert.rejects(decryptRoomFileHistory(randomUUID(), 2, current, envelope));
  await assert.rejects(decryptRoomFileHistory(roomId, 3, current, envelope));
  await assert.rejects(decryptRoomFileHistory(roomId, 2, new Uint8Array(randomBytes(32)), envelope));
  await assert.rejects(encryptRoomFileHistory(roomId, 2, current, {
    [oldFingerprint]: roomFileBase64(new Uint8Array(randomBytes(32))),
  }));
});

test('failed credential transaction preserves the old key, history, and pending rotation', async () => {
  const roomId = randomUUID();
  const oldSecret = new Uint8Array(randomBytes(32));
  const nextSecret = new Uint8Array(randomBytes(32));
  const nextFingerprint = await roomFileFingerprint(nextSecret);
  const priorSecret = new Uint8Array(randomBytes(32));
  const oldHistory = { [await roomFileFingerprint(priorSecret)]: roomFileBase64(priorSecret) };
  const nextHistory = { [await roomFileFingerprint(oldSecret)]: roomFileBase64(oldSecret) };
  const stores = new Map<string, Map<IDBValidKey, unknown>>();
  stores.set('secrets', new Map<IDBValidKey, unknown>([[roomId, roomFileBase64(oldSecret)]]));
  stores.set('history', new Map<IDBValidKey, unknown>([
    [roomId, oldHistory],
    [`rotation:${roomId}`, { newFingerprint: nextFingerprint }],
  ]));
  stores.set('uploads', new Map<IDBValidKey, unknown>());
  let failHistoryWrite = true;
  const fakeIndexedDB = {
    open() {
      const request: Record<string, unknown> = {};
      const database = {
        objectStoreNames: { contains: (name: string) => stores.has(name) },
        close() {},
        transaction(names: string[] | string) {
          const allowed = new Set(Array.isArray(names) ? names : [names]);
          const staged: Array<() => void> = [];
          let aborted = false;
          const transaction: Record<string, unknown> = {};
          transaction.abort = () => {
            aborted = true;
          };
          transaction.objectStore = (name: string) => {
            if (!allowed.has(name)) throw new Error('Store not in transaction.');
            return {
              put(value: unknown, key: IDBValidKey) {
                if (failHistoryWrite && name === 'history' && key === roomId)
                  throw new Error('Simulated IndexedDB quota failure.');
                staged.push(() => stores.get(name)!.set(key, value));
              },
              delete(key: IDBValidKey) { staged.push(() => stores.get(name)!.delete(key)); },
              get(key: IDBValidKey) {
                const result: Record<string, unknown> = {};
                queueMicrotask(() => {
                  result.result = stores.get(name)!.get(key);
                  (result.onsuccess as (() => void) | undefined)?.();
                });
                return result;
              },
            };
          };
          setTimeout(() => {
            if (!aborted) for (const apply of staged) apply();
            const callback = (aborted ? transaction.onabort : transaction.oncomplete) as (() => void) | undefined;
            callback?.();
          }, 0);
          return transaction;
        },
      };
      queueMicrotask(() => {
        request.result = database;
        (request.onupgradeneeded as (() => void) | undefined)?.();
        (request.onsuccess as (() => void) | undefined)?.();
      });
      return request;
    },
  } as unknown as IDBFactory;
  const originalIndexedDB = globalThis.indexedDB;
  Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: fakeIndexedDB });
  try {
    await assert.rejects(commitRoomFileKeyState(roomId, nextSecret, nextHistory, nextFingerprint), /Simulated IndexedDB quota failure/);
    assert.equal(stores.get('secrets')!.get(roomId), roomFileBase64(oldSecret));
    assert.deepEqual(stores.get('history')!.get(roomId), oldHistory);
    assert.ok(stores.get('history')!.has(`rotation:${roomId}`));

    failHistoryWrite = false;
    await commitRoomFileKeyState(roomId, nextSecret, nextHistory, nextFingerprint);
    assert.equal(stores.get('secrets')!.get(roomId), roomFileBase64(nextSecret));
    assert.deepEqual(stores.get('history')!.get(roomId), nextHistory);
    assert.equal(stores.get('history')!.has(`rotation:${roomId}`), false);
  } finally {
    Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: originalIndexedDB });
  }
});
