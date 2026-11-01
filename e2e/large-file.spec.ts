import { mkdirSync, writeFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
test('250 MiB encrypted API publication and OPFS download preserve every byte', async ({ page }) => {
  await page.goto('/');
  const evidence = await page.evaluate(async () => {
    const url = '/client/roomCrypto.ts', apiUrl = '/client/api.ts';
    const c = await import(url), a = await import(apiUrl);
    const session = await a.startSession(); void session;
    const started = performance.now();
    const room = await a.api('/rooms', 'POST', { title: '250 MiB benchmark', description: '', expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    await a.api(`/rooms/${room.id}/open`, 'POST');
    const key = await c.createKey();
    await a.api(`/rooms/${room.id}/keys/owner`, 'POST', { publicKey: c.encodeBase64(key.publicKey) });
    const keys = await a.api(`/rooms/${room.id}/files/keys`);
    // Distinct deterministic bytes per chunk expose ordering and truncation mistakes.
    const parts = Array.from({ length: 250 }, (_, index) => new Uint8Array(1048576).fill(index));
    const file = new File(parts, '250-MiB-benchmark.bin');
    const plan = await c.prepareDistribution(file, room.id, crypto.randomUUID(), [{ id: keys.ownerRecipientId, publicKey: key.publicKey }]);
    await a.api(`/rooms/${room.id}/files`, 'POST', { fileId: plan.fileId });
    await a.api(`/rooms/${room.id}/files/${plan.fileId}/metadata`, 'PUT', { descriptor: plan.descriptor, envelopes: plan.envelopes });
    const hashes: string[] = [];
    for (let i = 0; i < 250; i++) {
      const chunk = await c.encryptDistributionChunk(plan, i);
      await a.apiBytes(`/rooms/${room.id}/files/${plan.fileId}/chunks/${i}`, 'PUT', chunk.ciphertext);
      hashes.push(chunk.sha256);
    }
    const manifestSha256 = await c.distributionManifest(plan, hashes);
    await a.api(`/rooms/${room.id}/files/${plan.fileId}/complete`, 'POST', { chunkCount: 250, manifestSha256 });
    const uploadMs = performance.now() - started;
    const item = (await a.api(`/rooms/${room.id}/files`)).files[0];
    let savedBytes = 0;
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: async () => ({
      createWritable: async () => new WritableStream<Uint8Array>({ write(chunk) {
        for (let i = 0; i < chunk.length; i++) {
          if (chunk[i] !== Math.floor((savedBytes + i) / 1048576)) throw new Error('Plaintext byte mismatch.');
        }
        savedBytes += chunk.length;
      } }),
    }) });
    const downloadStart = performance.now();
    await c.decryptRoomFileToDownload(room.id, item, key, async (index: number) => {
      const response = await a.apiBytes(`/rooms/${room.id}/files/${plan.fileId}/chunks/${index}`);
      return { bytes: response.bytes, sha256: response.sha256 };
    }, () => undefined);
    const downloadMs = performance.now() - downloadStart;
    const root = await (await navigator.storage.getDirectory()).getDirectoryHandle('portkey-verified-downloads');
    const entries: string[] = []; for await (const name of (root as FileSystemDirectoryHandle & { keys(): AsyncIterableIterator<string> }).keys()) entries.push(name);
    await a.api(`/rooms/${room.id}/files/${plan.fileId}`, 'DELETE');
    await a.api(`/rooms/${room.id}/close`, 'POST');
    return { plaintextBytes: file.size, encryptedBytes: item.encryptedBytes, savedBytes, chunkCount: 250, uploadMs, downloadMs, remainingStagedFiles: entries.filter(name => /^portkey-.*\.tmp$/.test(name)).length, browser: navigator.userAgent };
  });
  expect(evidence.plaintextBytes).toBe(250 * 1048576);
  expect(evidence.savedBytes).toBe(evidence.plaintextBytes);
  expect(evidence.encryptedBytes).toBe(evidence.plaintextBytes + 250 * 16);
  expect(evidence.remainingStagedFiles).toBe(0);
  mkdirSync('benchmark-results', { recursive: true });
  writeFileSync('benchmark-results/250-mib.json', JSON.stringify({ ...evidence, measuredAt: new Date().toISOString() }, null, 2));
});
