import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  commitRoomFileKeyState,
  decryptRoomFileHistory,
  encryptRoomFileHistory,
  roomFileBase64,
  roomFileFingerprint,
  savePendingRoomFileRotation,
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
  const oldFingerprint = await roomFileFingerprint(oldSecret);
  const priorSecret = new Uint8Array(randomBytes(32));
  const oldHistory = { [await roomFileFingerprint(priorSecret)]: roomFileBase64(priorSecret) };
  const nextHistory = { [await roomFileFingerprint(oldSecret)]: roomFileBase64(oldSecret) };
  const stores = new Map<string, Map<IDBValidKey, unknown>>();
  stores.set('secrets', new Map<IDBValidKey, unknown>([[roomId, roomFileBase64(oldSecret)]]));
  stores.set('history', new Map<IDBValidKey, unknown>([
    [roomId, oldHistory],
    [`rotation:${roomId}`, { newFingerprint: nextFingerprint }],
    [`key-state:${roomId}`, { epoch: 1, fingerprint: oldFingerprint }],
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
              add(value: unknown, key: IDBValidKey) {
                const request: Record<string, unknown> = {};
                if (stores.get(name)!.has(key)) {
                  queueMicrotask(() => {
                    request.error = new DOMException('Key already exists.', 'ConstraintError');
                    (request.onerror as (() => void) | undefined)?.();
                    aborted = true;
                    (transaction.onabort as (() => void) | undefined)?.();
                  });
                } else {
                  staged.push(() => stores.get(name)!.set(key, value));
                }
                return request;
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
    const pending = {
      expectedFingerprint: 'a'.repeat(64),
      newFingerprint: nextFingerprint,
      secret: roomFileBase64(nextSecret),
      historyEnvelope: 'pending-envelope',
      epoch: 2,
    };
    const otherRoomId = randomUUID();
    await savePendingRoomFileRotation(otherRoomId, pending);
    assert.deepEqual(stores.get('history')!.get(`rotation:${otherRoomId}`), pending);
    await assert.rejects(
      savePendingRoomFileRotation(otherRoomId, { ...pending, secret: roomFileBase64(oldSecret) }),
      /Another tab already saved a rotation candidate/,
    );
    assert.deepEqual(stores.get('history')!.get(`rotation:${otherRoomId}`), pending);

    await assert.rejects(
      commitRoomFileKeyState(roomId, nextSecret, nextHistory, 2, nextFingerprint),
      /Simulated IndexedDB quota failure/,
    );
    assert.equal(stores.get('secrets')!.get(roomId), roomFileBase64(oldSecret));
    assert.deepEqual(stores.get('history')!.get(roomId), oldHistory);
    assert.ok(stores.get('history')!.has(`rotation:${roomId}`));

    failHistoryWrite = false;
    await commitRoomFileKeyState(roomId, nextSecret, nextHistory, 2, nextFingerprint);
    assert.equal(stores.get('secrets')!.get(roomId), roomFileBase64(nextSecret));
    assert.deepEqual(stores.get('history')!.get(roomId), nextHistory);
    assert.equal(stores.get('history')!.has(`rotation:${roomId}`), false);
    assert.deepEqual(stores.get('history')!.get(`key-state:${roomId}`), {
      epoch: 2,
      fingerprint: nextFingerprint,
    });

    const newestSecret = new Uint8Array(randomBytes(32));
    const newestFingerprint = await roomFileFingerprint(newestSecret);
    const newestHistory = {
      ...nextHistory,
      [nextFingerprint]: roomFileBase64(nextSecret),
    };
    await commitRoomFileKeyState(roomId, newestSecret, newestHistory, 3);
    const newestPending = {
      expectedFingerprint: nextFingerprint,
      newFingerprint: newestFingerprint,
      secret: roomFileBase64(newestSecret),
      historyEnvelope: 'newest-envelope',
      epoch: 3,
    };
    await savePendingRoomFileRotation(roomId, newestPending);
    const delayedCommit = commitRoomFileKeyState.bind(
      null,
      roomId,
      nextSecret,
      nextHistory,
      2,
      nextFingerprint,
    );
    await assert.rejects(
      delayedCommit(),
      /newer shared-file key is already stored/,
    );
    assert.equal(stores.get('secrets')!.get(roomId), roomFileBase64(newestSecret));
    assert.deepEqual(stores.get('history')!.get(roomId), newestHistory);
    assert.deepEqual(stores.get('history')!.get(`key-state:${roomId}`), {
      epoch: 3,
      fingerprint: newestFingerprint,
    });
    assert.deepEqual(stores.get('history')!.get(`rotation:${roomId}`), newestPending);

    await commitRoomFileKeyState(roomId, newestSecret, newestHistory, 3);
    const conflictingSecret = new Uint8Array(randomBytes(32));
    const conflictingHistory = {
      ...newestHistory,
      [newestFingerprint]: roomFileBase64(newestSecret),
    };
    await assert.rejects(
      commitRoomFileKeyState(roomId, conflictingSecret, conflictingHistory, 3),
      /newer shared-file key is already stored/,
    );
    assert.equal(stores.get('secrets')!.get(roomId), roomFileBase64(newestSecret));
    assert.deepEqual(stores.get('history')!.get(roomId), newestHistory);
    assert.deepEqual(stores.get('history')!.get(`key-state:${roomId}`), {
      epoch: 3,
      fingerprint: newestFingerprint,
    });
    assert.deepEqual(stores.get('history')!.get(`rotation:${roomId}`), newestPending);
  } finally {
    Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: originalIndexedDB });
  }
});
