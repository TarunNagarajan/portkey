import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

const LARGE_FILE_SIZE = 51 * 1024 * 1024;
const FILL_BYTE = 0x31;

test('room file crypto streams authenticated downloads above 50 MiB through OPFS', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.evaluate(() => {
    Object.defineProperty(window, 'showSaveFilePicker', {
      configurable: true,
      value: undefined,
    });
  });

  const downloadReady = page.waitForEvent('download');
  const prepared = await page.evaluate(async ({ fileSize, fillByte }) => {
    const storage = navigator.storage as StorageManager & {
      getDirectory?: () => Promise<FileSystemDirectoryHandle>;
    };
    if (!storage.getDirectory) throw new Error('The browser does not support OPFS.');
    const roomId = crypto.randomUUID();
    const masterKey = crypto.getRandomValues(new Uint8Array(32));
    const sourceBytes = new Uint8Array(fileSize);
    sourceBytes.fill(fillByte);
    const sourceFile = new File([sourceBytes.buffer], 'large-room-file.bin', {
      type: 'application/octet-stream',
    });
    const moduleUrl = '/client/roomFileCrypto.ts';
    const cryptoModule = await import(moduleUrl);
    const plan = await cryptoModule.prepareRoomFile(sourceFile, roomId, masterKey);
    const manifestSha256 = await cryptoModule.roomFileManifest(plan);
    await cryptoModule.decryptRoomFileToDownload(
      roomId,
      {
        id: plan.id,
        descriptor: plan.descriptor,
        chunkCount: plan.chunkCount,
        manifestSha256,
      },
      masterKey,
      async (index: number) => {
        const bytes = await cryptoModule.loadRoomFileCipherChunk(plan.id, index);
        if (!bytes) throw new Error(`Missing locally encrypted test chunk ${index}.`);
        return { bytes, sha256: await cryptoModule.hexDigest(bytes) };
      },
      () => undefined,
    );
    return { id: plan.id, filename: sourceFile.name };
  }, { fileSize: LARGE_FILE_SIZE, fillByte: FILL_BYTE });

  const download = await downloadReady;
  expect(download.suggestedFilename()).toBe(prepared.filename);
  const output = await readFile((await download.path())!);
  expect(output.byteLength).toBe(LARGE_FILE_SIZE);
  expect(createHash('sha256').update(output).digest('hex')).toBe(
    createHash('sha256').update(Buffer.alloc(LARGE_FILE_SIZE, FILL_BYTE)).digest('hex'),
  );

  await page.evaluate(async ({ id }) => {
    const moduleUrl = '/client/roomFileCrypto.ts';
    const cryptoModule = await import(moduleUrl);
    await cryptoModule.clearRoomFilePlan(id);
    await cryptoModule.clearRoomFileDownloadCopies();
  }, { id: prepared.id });
});
