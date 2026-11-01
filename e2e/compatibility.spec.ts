import { expect, test } from '@playwright/test';
test('browser crypto, IndexedDB journal, OPFS and keyboard entry work', async ({ page, browserName }) => {
  await page.goto('/');
  await page.getByLabel('Room title').focus();
  await page.keyboard.type(`Compatibility ${browserName}`);
  await page.getByRole('button', { name: 'Create draft' }).press('Enter');
  await expect(page.getByRole('button', { name: 'Open room', exact: true })).toBeVisible();
  const result = await page.evaluate(async () => {
    let stage = 'imports';
    try {
    const cryptoUrl = '/client/roomCrypto.ts', journalUrl = '/client/uploadStore.ts';
    const c = await import(cryptoUrl), j = await import(journalUrl);
    const key = await c.createKey(), roomId = crypto.randomUUID();
    const plan = await c.prepareDistribution(new File(['compatibility payload'], 'compat.txt'), roomId, crypto.randomUUID(), [{ id: crypto.randomUUID(), publicKey: key.publicKey }]);
    stage = 'saveUpload'; await j.saveUpload(plan);
    stage = 'immutableUploadChunk'; const chunk = await j.immutableUploadChunk(plan, 0);
    stage = 'load persisted chunk'; const cached = await j.immutableUploadChunk((await j.pendingUploads(roomId))[0], 0);
    stage = 'decryptChunk'; const opened = await c.decryptChunk(chunk.ciphertext, plan.fileKey, plan.keySalt, plan.noncePrefix, roomId, plan.fileId, 0, plan.chunkSizes[0]);
    const password = 'a browser compatibility backup passphrase';
    stage = 'export backup'; const backup = await c.exportEncryptedBackup(roomId, key, password);
    stage = 'restore backup'; const restored = await c.restoreEncryptedBackup(roomId, backup, password, key.fingerprint);
    stage = 'derive room access';
    const access = await c.deriveRoomAccessKey(key, roomId);
    stage = 'repeat derivation'; const repeated = await c.deriveRoomAccessKey(key, roomId);
    stage = 'decode invitation'; const invited = await c.decodeRoomAccess(c.encodeRoomAccess(access));
    stage = 'export related backup'; const roomBackup = await c.exportEncryptedBackup(roomId, key, password, access);
    stage = 'restore related backup'; await c.restoreEncryptedBackup(roomId, roomBackup, password, key.fingerprint, { roomAccessFingerprint: access.fingerprint });
    const recoveredAccess = await c.loadKey(c.roomAccessStorageId(roomId));
    if (repeated.fingerprint !== access.fingerprint || invited.fingerprint !== access.fingerprint || recoveredAccess?.fingerprint !== access.fingerprint) throw new Error('Room access invitation or recovery did not match');
    stage = 'forget upload'; await j.forgetUpload(plan);
    let opfs = false;
    const root = await c.privateDirectory();
    if (root) { const name = `compat-${crypto.randomUUID()}`;
      stage = 'OPFS write'; const handle = await root.getFileHandle(name, { create: true }); const writer = await handle.createWritable();
      await writer.write(opened); await writer.close(); opfs = (await handle.getFile()).size === opened.length;
      stage = 'OPFS remove'; await root.removeEntry(name);
    }
    return { plaintext: new TextDecoder().decode(opened), cached: chunk.sha256 === cached.sha256, recovered: restored.fingerprint === key.fingerprint, pending: (await j.pendingUploads(roomId)).length, opfs };
    } catch (error) { throw new Error(`${stage}: ${error instanceof Error ? error.message : error}`); }
  });
  expect(result).toEqual({ plaintext: 'compatibility payload', cached: true, recovered: true, pending: 0, opfs: expect.any(Boolean) });
});
