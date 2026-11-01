import { expect, test } from '@playwright/test';
test('offline status, missing private storage, quota failures and abandoned reservations stay recoverable', async ({ page, context }) => {
  await page.goto('/');
  await expect(page.getByLabel('Room title')).toBeVisible();
  await context.setOffline(true);
  await expect(page.getByText('You are offline.', { exact: false })).toBeVisible();
  await context.setOffline(false);
  await expect(page.getByText('You are offline.', { exact: false })).toHaveCount(0);
  const result = await page.evaluate(async () => {
    const cryptoUrl = '/client/roomCrypto.ts', journalUrl = '/client/uploadStore.ts';
    const c = await import(cryptoUrl), j = await import(journalUrl);
    const room = crypto.randomUUID(), key = await c.createKey();
    const plan = await c.prepareDistribution(new File([new Uint8Array(51 * 1048576)], 'large.bin'), room, crypto.randomUUID(), [{ id: crypto.randomUUID(), publicKey: key.publicKey }]);
    const original = navigator.storage.getDirectory?.bind(navigator.storage);
    const item = { id: plan.fileId, descriptor: plan.descriptor, envelope: plan.envelopes[0], chunkCount: plan.chunkSizes.length, manifestSha256: '0'.repeat(64) };
    let withoutStorage = false, quota = false, reads = 0;
    Object.defineProperty(navigator.storage, 'getDirectory', { configurable: true, value: undefined });
    try { await c.decryptRoomFileToDownload(room, item, key, async () => { reads++; throw new Error('Must not read'); }, () => undefined); }
    catch (error) { withoutStorage = /50 MiB/.test(String(error)); }
    Object.defineProperty(navigator.storage, 'getDirectory', { configurable: true, value: async () => { throw new DOMException('No space', 'QuotaExceededError'); } });
    try { await j.saveUpload(plan); } catch (error) { quota = error instanceof DOMException && error.name === 'QuotaExceededError'; }
    Object.defineProperty(navigator.storage, 'getDirectory', { configurable: true, value: original });
    const small = await c.prepareDistribution(new File(['reserved'], 'small.txt'), room, crypto.randomUUID(), [{ id: crypto.randomUUID(), publicKey: key.publicKey }]);
    await j.saveUpload(small);
    await new Promise<void>((resolve, reject) => {
      const open = indexedDB.open('portkey-upload-journal-v1', 1);
      open.onsuccess = () => { const db = open.result, tx = db.transaction('chunks', 'readwrite');
        tx.objectStore('chunks').put('reserved', `${room}:${small.fileId}:0`);
        tx.oncomplete = () => { db.close(); resolve(); }; tx.onabort = () => { db.close(); reject(tx.error); };
      };
    });
    let reservationBlocked = false;
    try { await j.immutableUploadChunk(small, 0); } catch (error) { reservationBlocked = /Discard this upload/.test(String(error)); }
    await j.forgetUpload(small);
    return { withoutStorage, quota, reads, reservationBlocked, pending: (await j.pendingUploads(room)).length };
  });
  expect(result).toEqual({ withoutStorage: true, quota: true, reads: 0, reservationBlocked: true, pending: 0 });
});
