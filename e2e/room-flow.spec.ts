import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

test('encrypted submissions require a pinned organizer key and round-trip privately', async ({
  page,
  browser,
}) => {
  test.setTimeout(120_000);
  const transferred: Buffer[] = [];
  page.on('request', (request) => {
    const data = request.postDataBuffer();
    if (data) transferred.push(data);
  });
  await page.goto('/');
  await page.getByLabel('Room title').fill('Encrypted review');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const ownerRoomUrl = page.url();
  const ownerRoomPath = new URL(ownerRoomUrl).pathname;
  await page.getByRole('button', { name: 'Enable encrypted inbox' }).click();
  await expect(
    page.getByText('Encrypted inbox enabled.', { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Download encrypted key backup' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  const invite = await page.locator('.join-link').getAttribute('href');
  expect(invite).toMatch(/#key=[a-f0-9]{64}$/);

  const participantContext = await browser.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true,
    hasTouch: true,
  });
  const participant = await participantContext.newPage();
  participant.on('request', (request) => {
    const data = request.postDataBuffer();
    if (data) transferred.push(data);
  });
  await participant.goto(invite!);
  await expect(participant).toHaveURL(/#key=[a-f0-9]{64}$/);
  await participant.getByLabel('Your label').fill('Private submitter');
  await participant.getByRole('button', { name: 'Request access' }).click();
  await expect(
    participant.getByText(
      'Waiting for organizer approval. This page updates automatically.',
    ),
  ).toBeVisible();
  const memberRow = page
    .getByRole('row')
    .filter({ hasText: 'Private submitter' });
  await expect(memberRow).toBeVisible();
  await memberRow.getByRole('button', { name: 'Approve', exact: true }).click();
  await participant.getByRole('link', { name: 'Enter room' }).click();
  await expect(
    participant.getByRole('heading', { name: 'Encrypted submission inbox' }),
  ).toBeVisible();
  await expect(
    participant.getByRole('button', { name: 'Submit file privately' }),
  ).toBeVisible();

  const fixture = {
    name: 'draft notes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('private contents with no server-side filename\n'.repeat(50_000)),
  };
  await participant
    .getByLabel('Choose a file (up to 250 MiB)')
    .setInputFiles(fixture);
  const chunkEndpoint = '**/api' + ownerRoomPath + '/submissions/*/chunks/0';
  let originalCiphertext: Buffer | null = null;
  let signalInterrupted: () => void = () => {};
  const interrupted = new Promise<void>((resolve) => {
    signalInterrupted = resolve;
  });
  await participant.route(chunkEndpoint, async (route) => {
    originalCiphertext = route.request().postDataBuffer();
    await route.fulfill({
      status: 429,
      headers: { 'Retry-After': '60' },
      json: {
        error: { code: 'RATE_LIMITED', message: 'Wait before retrying.' },
      },
    });
    signalInterrupted();
  });
  await participant
    .getByRole('button', { name: 'Submit file privately' })
    .click();
  await interrupted;
  await participant.getByRole('button', { name: 'Pause transfer' }).click();
  await expect(participant.getByRole('alert')).toContainText(
    'Transfer paused.',
  );
  await participant.unroute(chunkEndpoint);
  let lostCompletion = false;
  await participant.route(
    '**/api' + ownerRoomPath + '/submissions/*/complete',
    async (route) => {
      if (!lostCompletion) {
        lostCompletion = true;
        const response = await route.fetch();
        expect(response.status()).toBe(200);
        await route.abort('failed');
      } else await route.continue();
    },
  );
  const retryRequest = participant.waitForRequest((request) =>
    /\/submissions\/[^/]+\/chunks\/0$/.test(request.url()),
  );
  await participant
    .getByRole('button', { name: 'Resume with selected file' })
    .click();
  expect(
    (await retryRequest).postDataBuffer()?.equals(originalCiphertext!),
  ).toBe(true);
  await expect(participant.getByText(/Submission accepted at/)).toBeVisible({
    timeout: 30_000,
  });
  expect(lostCompletion).toBe(true);
  await expect(
    page.getByRole('button', { name: 'Decrypt and download' }),
  ).toHaveCount(1, { timeout: 20_000 });

  await page
    .getByLabel('Backup passphrase')
    .last()
    .fill('a long browser-only backup passphrase');
  const backupDownload = page.waitForEvent('download');
  await page
    .getByRole('button', { name: 'Download encrypted key backup' })
    .click();
  const backup = await backupDownload;
  expect(backup.suggestedFilename()).toMatch(/key-backup\.json$/);
  const backupPath = await backup.path();
  expect(backupPath).toBeTruthy();
  const backupText = await (
    await import('node:fs/promises')
  ).readFile(backupPath!, 'utf8');
  expect(backupText).not.toContain('privateKey');
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase('portkey-private-keys');
        request.onsuccess =
          request.onerror =
          request.onblocked =
            () => resolve();
      }),
  );
  await page.reload();
  await expect(
    page.getByText(/registered private key is not stored/i),
  ).toBeVisible();
  await page
    .getByLabel('Backup passphrase')
    .fill('a long browser-only backup passphrase');
  await page.getByLabel('Encrypted key backup').setInputFiles({
    name: 'recovery.json',
    mimeType: 'application/json',
    buffer: Buffer.from(backupText),
  });
  await expect(
    page.getByText('The backup key matches the registered room key.'),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Decrypt and download' }),
  ).toBeVisible();
  await page.screenshot({
    path: '../outputs/Portkey_EncryptedInbox_Desktop.png',
    fullPage: true,
  });
  await participant.screenshot({
    path: '../outputs/Portkey_EncryptedInbox_Mobile.png',
    fullPage: true,
  });
  await page.evaluate(() => {
    const target = window as Window & {
      __savedFile?: { chunks: Uint8Array[]; closed: boolean };
      showSaveFilePicker?: (options: unknown) => Promise<unknown>;
    };
    Object.defineProperty(target, '__savedFile', {
      configurable: true,
      writable: true,
      value: { chunks: [], closed: false },
    });
    Object.defineProperty(target, 'showSaveFilePicker', {
      configurable: true,
      value: async () => ({
        createWritable: async () =>
          new WritableStream({
            write: (chunk: Uint8Array) => {
              target.__savedFile?.chunks.push(chunk.slice());
            },
            close: () => { if (target.__savedFile) target.__savedFile.closed = true; },
          }),
      }),
    });
  });

  await page.route(
    '**/api' + ownerRoomPath + '/submissions/*/chunks/*',
    async (route) => {
      const response = await route.fetch();
      const body = Buffer.from(await response.body());
      body[0] ^= 0xff;
      await route.fulfill({ response, body });
    },
  );
  await page.getByRole('button', { name: 'Decrypt and download' }).click();
  await expect(page.getByRole('alert')).toContainText(
    /integrity|manifest|authenticate/i,
  );
  expect(
    await page.evaluate(
      () => (window as Window & { __savedFile?: { chunks: Uint8Array[]; closed: boolean } }).__savedFile,
    ),
  ).toEqual({ chunks: [], closed: false });
  await page.unroute('**/api' + ownerRoomPath + '/submissions/*/chunks/*');
  await page.getByRole('button', { name: 'Decrypt and download' }).click();
  await expect
    .poll(() =>
      page.evaluate(async () => {
        const saved = (window as Window & { __savedFile?: { chunks: Uint8Array[]; closed: boolean } }).__savedFile;
        if (!saved?.closed) return null;
        const bytes = new Uint8Array(saved.chunks.reduce((total, chunk) => total + chunk.length, 0));
        let offset = 0;
        for (const chunk of saved.chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        const digest = await crypto.subtle.digest('SHA-256', bytes);
        return { size: bytes.length, digest: Array.from(new Uint8Array(digest)) };
      }),
    )
    .toEqual({ size: fixture.buffer.length, digest: [...createHash('sha256').update(fixture.buffer).digest()] });
  await page.evaluate(() =>
    Object.defineProperty(window, 'showSaveFilePicker', {
      configurable: true,
      value: undefined,
    }),
  );
  const actualDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Decrypt and download' }).click();
  const downloaded = await actualDownload;
  expect(downloaded.suggestedFilename()).toBe(fixture.name);
  expect(
    await (
      await import('node:fs/promises')
    ).readFile((await downloaded.path())!, 'utf8'),
  ).toBe(fixture.buffer.toString());
  await page
    .getByRole('button', { name: 'Remove local download copies' })
    .click();
  await expect(page.getByText('1 local download copy removed.')).toBeVisible();
  for (const body of transferred) {
    expect(body.includes(fixture.buffer)).toBe(false);
    expect(body.includes(Buffer.from(fixture.name))).toBe(false);
    expect(
      body.includes(Buffer.from('a long browser-only backup passphrase')),
    ).toBe(false);
  }
  const fake = await page.evaluate(async () => {
    const moduleUrl = '/client/submissionCrypto.ts';
    const cryptoModule = await import(moduleUrl);
    const pair = await cryptoModule.createKey();
    return {
      ownerPublicKey: cryptoModule.encodeBase64(pair.publicKey),
      ownerFingerprint: pair.fingerprint,
    };
  });
  await page.route('**/api' + ownerRoomPath + '/submissions/keys', (route) =>
    route.fulfill({ json: fake }),
  );
  await page.reload();
  await expect(page.getByRole('alert')).toContainText(
    'saved key does not match',
  );
  await expect(page.locator('.join-link')).not.toHaveAttribute('href', /#key=/);
  await page.unroute('**/api' + ownerRoomPath + '/submissions/keys');
  await page.reload();
  await expect(page.locator('.join-link')).toHaveAttribute(
    'href',
    /#key=[a-f0-9]{64}$/,
  );
  await participant.goto(ownerRoomUrl + '#key=' + '0'.repeat(64));
  await expect(participant.getByRole('alert')).toContainText(
    'invitation key does not match',
  );
  await expect(
    participant.getByRole('button', { name: 'Submit file privately' }),
  ).toHaveCount(0);
  await participant.goto(ownerRoomUrl);
  await expect(
    participant.getByRole('button', { name: 'Submit file privately' }),
  ).toBeVisible();
  await participant.evaluate(
    (roomId) => localStorage.removeItem(`portkey-organizer-key:${roomId}`),
    ownerRoomPath.split('/').at(-1)!,
  );
  await participant.reload();
  await expect(
    participant.getByRole('button', { name: 'Submit file privately' }),
  ).toHaveCount(0);
  await participant
    .getByRole('button', {
      name: 'I verified this fingerprint with the organizer',
    })
    .click();
  await expect(
    participant.getByRole('button', { name: 'Submit file privately' }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page
      .locator('.private-inbox')
      .evaluate((element) => element.scrollWidth <= element.clientWidth),
  ).toBe(true);
  await page.setViewportSize({ width: 1280, height: 900 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await participantContext.close();
});

test('browser crypto rejects altered contexts and lost retry chunks, and protects backup keys', async ({
  page,
}) => {
  await page.goto('/');
  const result = await page.evaluate(async () => {
    const moduleUrl = '/client/submissionCrypto.ts';
    const c = await import(moduleUrl);
    const room = crypto.randomUUID();
    const id = crypto.randomUUID();
    const owner = await c.createKey();
    const submitter = await c.createKey();
    const file = new File([new Uint8Array(1048577).fill(43)], 'two chunks.bin');
    const plan = await c.prepareSubmission(
      file,
      room,
      id,
      owner.publicKey,
      owner.fingerprint,
      submitter,
    );
    const chunk = await c.encryptUploadChunk(file, plan, 0);
    const failures: string[] = [];
    async function mustReject(label: string, work: () => Promise<unknown>) {
      try {
        await work();
        failures.push(label);
      } catch {}
    }
    const context = (roomId: string, purpose = 'submission-file-key') =>
      c.encode(
        JSON.stringify({
          protocol: 'portkey-private-submission-v1',
          roomId,
          objectId: id,
          recipientFingerprint: owner.fingerprint,
          purpose,
        }),
      );
    const key = await c.hpkeOpen(owner, plan.ownerEnvelope, context(room));
    const descriptor = await c.decryptDescriptor(
      plan.descriptor,
      key,
      room,
      id,
    );
    const plain = await c.decryptChunk(
      chunk,
      key,
      descriptor.keySalt,
      descriptor.noncePrefix,
      room,
      id,
      0,
      descriptor.chunkSizes[0],
    );
    await mustReject('room substitution', () =>
      c.hpkeOpen(owner, plan.ownerEnvelope, context(crypto.randomUUID())),
    );
    await mustReject('purpose substitution', () =>
      c.hpkeOpen(owner, plan.ownerEnvelope, context(room, 'another-purpose')),
    );
    await mustReject('recipient substitution', () =>
      c.hpkeOpen(submitter, plan.ownerEnvelope, context(room)),
    );
    await mustReject('chunk reordering', () =>
      c.decryptChunk(
        chunk,
        key,
        descriptor.keySalt,
        descriptor.noncePrefix,
        room,
        id,
        1,
        descriptor.chunkSizes[0],
      ),
    );
    await mustReject('chunk truncation', () =>
      c.decryptChunk(
        chunk.slice(0, -1),
        key,
        descriptor.keySalt,
        descriptor.noncePrefix,
        room,
        id,
        0,
        descriptor.chunkSizes[0],
      ),
    );
    const altered = Uint8Array.from(chunk);
    altered[0] ^= 1;
    await mustReject('chunk modification', () =>
      c.decryptChunk(
        altered,
        key,
        descriptor.keySalt,
        descriptor.noncePrefix,
        room,
        id,
        0,
        descriptor.chunkSizes[0],
      ),
    );
    const metadataBytes = c.decodeBase64(plan.descriptor);
    metadataBytes[metadataBytes.length - 1] ^= 1;
    await mustReject('metadata modification', () =>
      c.decryptDescriptor(c.encodeBase64(metadataBytes), key, room, id),
    );
    const envelopeBytes = c.decodeBase64(plan.ownerEnvelope.ciphertext);
    envelopeBytes[0] ^= 1;
    await mustReject('envelope modification', () =>
      c.hpkeOpen(
        owner,
        { ...plan.ownerEnvelope, ciphertext: c.encodeBase64(envelopeBytes) },
        context(room),
      ),
    );
    const changedTail = new Uint8Array(1048577).fill(43);
    changedTail[changedTail.length - 1] = 44;
    await mustReject('changed unencrypted tail', () =>
      c.encryptUploadChunk(
        new File([changedTail], 'changed tail.bin'),
        plan,
        1,
      ),
    );
    const second = await c.encryptUploadChunk(file, plan, 1);
    const retry = await c.encryptUploadChunk(file, plan, 0);
    const retryIdentical = (await c.digest(chunk)) === (await c.digest(retry));
    await new Promise<void>((resolve, reject) => {
      const opening = indexedDB.open('portkey-private-keys', 2);
      opening.onsuccess = () => {
        const db = opening.result;
        const tx = db.transaction('uploads', 'readwrite');
        tx.objectStore('uploads').delete(`chunk:${id}:0`);
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onabort = () => {
          db.close();
          reject(tx.error);
        };
      };
      opening.onerror = () => reject(opening.error);
    });
    await mustReject('lost ciphertext reused nonce', () =>
      c.encryptUploadChunk(file, plan, 0),
    );
    await mustReject('changed file reused nonce', () =>
      c.encryptUploadChunk(
        new File([new Uint8Array(1048577).fill(44)], 'changed.bin'),
        plan,
        0,
      ),
    );
    const password = 'a long unique testing backup passphrase';
    const backup = await c.exportEncryptedBackup(room, owner, password);
    await mustReject('wrong backup password', () =>
      c.restoreEncryptedBackup(
        room,
        backup,
        'a different long testing password',
        owner.fingerprint,
      ),
    );
    await mustReject('wrong room backup', () =>
      c.restoreEncryptedBackup(
        crypto.randomUUID(),
        backup,
        password,
        owner.fingerprint,
      ),
    );
    await mustReject('wrong registered key', () =>
      c.restoreEncryptedBackup(room, backup, password, submitter.fingerprint),
    );
    const restored = await c.restoreEncryptedBackup(
      room,
      backup,
      password,
      owner.fingerprint,
    );
    await mustReject('local key overwrite', () =>
      c.retainPendingKey(room, submitter),
    );
    const saved = await c.loadKey(room);
    const emptyId = crypto.randomUUID();
    const emptyPlan = await c.prepareSubmission(
      new File([], 'empty.txt'),
      room,
      emptyId,
      owner.publicKey,
      owner.fingerprint,
      submitter,
    );
    const emptyChunk = await c.encryptUploadChunk(
      new File([], 'empty.txt'),
      emptyPlan,
      0,
    );
    const emptyPlain = await c.decryptChunk(
      emptyChunk,
      c.decodeBase64(emptyPlan.fileKey),
      emptyPlan.keySalt,
      emptyPlan.noncePrefix,
      room,
      emptyId,
      0,
      0,
    );
    await c.clearUpload(id);
    await c.clearUpload(emptyId);
    await new Promise<void>((resolve, reject) => {
      const removal = indexedDB.deleteDatabase('portkey-private-keys');
      removal.onsuccess = () => resolve();
      removal.onerror = () => reject(removal.error);
      removal.onblocked = () =>
        reject(new Error('Key database connection leaked.'));
    });
    return {
      failures,
      plainLength: plain.length,
      secondLength: second.length,
      retryIdentical,
      restored:
        restored.fingerprint === owner.fingerprint &&
        saved?.fingerprint === owner.fingerprint,
      emptyLength: emptyPlain.length,
    };
  });
  expect(result).toEqual({
    failures: [],
    plainLength: 1048576,
    secondLength: 17,
    retryIdentical: true,
    restored: true,
    emptyLength: 0,
  });
});

test('organizer creates and manages a room; a mobile participant requests access', async ({
  page,
  browser,
}) => {
  const failures: string[] = [];
  page.on('pageerror', (error) => failures.push(error.message));
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Your rooms', exact: true }),
  ).toBeVisible();
  await page.getByLabel('Room title').fill('Design workshop');
  await page
    .getByLabel('Public description')
    .fill('Bring your draft. Use a team label to request entry.');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const roomPath = new URL(page.url()).pathname;
  await page.getByRole('button', { name: 'Edit details' }).click();
  await page
    .getByLabel('Public description')
    .fill('A temporary room for workshop participants.');
  await page.getByRole('button', { name: 'Save details' }).click();
  await expect(
    page.getByText('A temporary room for workshop participants.'),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  const qr = page.getByRole('img', {
    name: 'QR code for this room’s join link',
  });
  await expect(qr).toHaveAttribute('src', /^data:image\/png/);
  const link = await page.locator('.join-link').getAttribute('href');
  expect(link).toBeTruthy();

  const mobile = await browser.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true,
    hasTouch: true,
  });
  const participant = await mobile.newPage();
  participant.on('pageerror', (error) => failures.push(error.message));
  await participant.goto(link!);
  await participant.getByLabel('Your label').fill('Team Cedar');
  await participant.getByRole('button', { name: 'Request access' }).click();
  await expect(participant.getByRole('status')).toContainText(
    'Waiting for organizer approval',
  );
  const unauthorized = await mobile.request.get(
    `${new URL(page.url()).origin}/api${roomPath}`,
  );
  expect(unauthorized.status()).toBe(403);

  const row = page.getByRole('row').filter({ hasText: 'Team Cedar' });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(
    participant.getByRole('link', { name: 'Enter room' }),
  ).toBeVisible();
  await participant.getByRole('link', { name: 'Enter room' }).click();
  await expect(
    participant.getByText('Your organizer-approved access is active', {
      exact: false,
    }),
  ).toBeVisible();
  expect(
    await participant.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  const activity = page.getByRole('region', {
    name: 'Room activity',
    exact: true,
  });
  await expect(
    activity.getByText('Access approved', { exact: true }),
  ).toBeVisible();
  await expect(
    activity.getByText('Room details updated', { exact: true }),
  ).toBeVisible();
  await expect(
    participant.getByRole('heading', { name: 'Room activity', exact: true }),
  ).toHaveCount(0);
  await page.screenshot({
    path: '../outputs/Portkey_Room_Management_Desktop.png',
    fullPage: true,
  });
  await page.screenshot({
    path: '../outputs/Portkey_Activity_Log_Desktop.png',
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: '../outputs/Portkey_Activity_Log_Mobile.png',
    fullPage: true,
  });
  await page.setViewportSize({ width: 1280, height: 720 });
  await participant.screenshot({
    path: '../outputs/Portkey_Room_Management_Mobile.png',
    fullPage: true,
  });

  await row.getByRole('button', { name: 'Remove access' }).click();
  await participant.reload();
  await expect(
    participant.getByText('Organizer approval is required.'),
  ).toBeVisible();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Close room', exact: true }).click();
  await expect(
    page.getByText('This room has closed. New admission is disabled.'),
  ).toBeVisible();
  await expect(
    activity.getByText('Room closed', { exact: true }),
  ).toBeVisible();
  await expect(
    activity.getByText('Access removed', { exact: true }),
  ).toBeVisible();
  await participant.goto(link!);
  await expect(
    participant.getByText('This room has closed.', { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByText('This room has closed. New admission is disabled.'),
  ).toBeVisible();
  expect(failures).toEqual([]);
  await mobile.close();
});

test('rooms can be searched, filtered and reused for another workshop', async ({
  page,
}) => {
  await page.goto('/');
  await page.getByLabel('Room title').fill('Photography basics');
  await page.getByLabel('Public description').fill('Lighting and composition');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const originalPath = new URL(page.url()).pathname;
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await page.getByRole('link', { name: 'Your rooms', exact: true }).click();
  await page.getByLabel('Room title').fill('Design sprint');
  await page
    .getByLabel('Public description')
    .fill('A new brief for the next event');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  await page.getByRole('link', { name: 'Your rooms', exact: true }).click();

  const rooms = page.locator('.room-list > li');
  await expect(rooms).toHaveCount(2);
  await page.getByLabel('Search rooms').fill('lighting');
  await expect(rooms).toHaveCount(1);
  await expect(rooms.first()).toContainText('Photography basics');
  await page.getByLabel('Filter rooms by status').selectOption('draft');
  await expect(
    page.getByRole('heading', { name: 'No matching rooms' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(rooms).toHaveCount(2);
  await page.getByLabel('Filter rooms by status').selectOption('open');
  await expect(rooms).toHaveCount(1);
  await page.getByLabel('Filter rooms by status').selectOption('all');
  await page.screenshot({
    path: '../outputs/Portkey_Workspace_Desktop.png',
    fullPage: true,
  });

  await page
    .getByRole('link', {
      name: 'Use Photography basics as template',
      exact: true,
    })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Reuse a room' }),
  ).toBeVisible();
  await expect(page.getByLabel('Room title')).toHaveValue('Photography basics');
  await expect(page.getByLabel('Public description')).toHaveValue(
    'Lighting and composition',
  );
  await page.getByLabel('Room title').fill('Photography — session two');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  expect(new URL(page.url()).pathname).not.toBe(originalPath);
  await expect(
    page.getByRole('button', { name: 'Open room', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'No requests yet' }),
  ).toBeVisible();
  await page.getByRole('link', { name: 'Your rooms', exact: true }).click();
  await expect(rooms).toHaveCount(3);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: '../outputs/Portkey_Workspace_Mobile.png',
    fullPage: true,
  });
});

test('activity supports older pages, recovery from read errors and returning to latest', async ({
  page,
}) => {
  await page.goto('/');
  await page.getByLabel('Room title').fill('Activity workshop');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const roomPath = new URL(page.url()).pathname;
  const origin = new URL(page.url()).origin;
  const activity = page.getByRole('region', {
    name: 'Room activity',
    exact: true,
  });
  await expect(
    activity.getByText('Room created', { exact: true }),
  ).toBeVisible();
  const endpoint = `${origin}/api${roomPath}/activity`;
  await page.route(endpoint, (route) =>
    route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({
        error: {
          code: 'UNAVAILABLE',
          message: 'Activity temporarily unavailable.',
        },
      }),
    }),
  );
  await expect(activity.getByRole('alert')).toHaveText(
    'Activity temporarily unavailable.',
  );
  await expect(
    page.getByRole('button', { name: 'Open room', exact: true }),
  ).toBeVisible();
  await page.unroute(endpoint);
  await activity.getByRole('button', { name: 'Retry activity' }).click();
  await expect(activity.getByRole('alert')).toHaveCount(0);

  const session = await page.request.post(`${origin}/api/session`, {
    headers: { Origin: origin },
  });
  const { csrfToken } = await session.json();
  const headers = { Origin: origin, 'X-CSRF-Token': csrfToken };
  const expiresAt = new Date(Date.now() + 3600_000).toISOString();
  for (let index = 1; index <= 22; index++) {
    const result = await page.request.patch(`${origin}/api${roomPath}`, {
      headers,
      data: {
        title: 'Activity workshop',
        description: `Revision ${index}`,
        expiresAt,
      },
    });
    expect(result.status()).toBe(200);
  }
  await expect(
    activity.getByRole('button', { name: 'Older activity' }),
  ).toBeVisible();
  const olderEndpoint = `${endpoint}?before=*`;
  await page.route(olderEndpoint, (route) =>
    route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({
        error: {
          code: 'UNAVAILABLE',
          message: 'Earlier activity unavailable.',
        },
      }),
    }),
  );
  await activity.getByRole('button', { name: 'Older activity' }).click();
  await expect(activity.getByRole('alert')).toHaveText(
    'Earlier activity unavailable.',
  );
  await expect(
    activity.getByText('Room details updated', { exact: true }),
  ).toHaveCount(0);
  await page.unroute(olderEndpoint);
  await activity.getByRole('button', { name: 'Retry activity' }).click();
  await expect(
    activity.getByText('Room created', { exact: true }),
  ).toBeVisible();
  await expect(
    activity.getByRole('button', { name: 'Back to latest' }),
  ).toBeVisible();
  await expect(
    activity.getByRole('button', { name: 'Older activity' }),
  ).toHaveCount(0);
  await page.request.post(`${origin}/api${roomPath}/open`, { headers });
  await activity.getByRole('button', { name: 'Back to latest' }).click();
  await expect(
    activity.getByText('Room opened', { exact: true }),
  ).toBeVisible();
  await expect(activity.getByText('Room created', { exact: true })).toHaveCount(
    0,
  );
  await page.route(olderEndpoint, () => {});
  const cancelled = page.waitForEvent('requestfailed', {
    predicate: (request) => request.url().startsWith(`${endpoint}?before=`),
  });
  await activity.getByRole('button', { name: 'Older activity' }).click();
  await expect(activity.getByRole('status')).toHaveText('Loading activity…');
  await activity.getByRole('button', { name: 'Back to latest' }).click();
  await expect(
    activity.getByText('Room opened', { exact: true }),
  ).toBeVisible();
  expect((await cancelled).failure()?.errorText).toContain('ERR_ABORTED');
  await page.unroute(olderEndpoint);
});
