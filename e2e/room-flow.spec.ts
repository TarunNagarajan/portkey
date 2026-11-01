import { test, expect, type Page } from '@playwright/test';

async function security(page: Page) {
  const details = page.locator('details.security-settings');
  if (await details.getAttribute('open') === null) await details.locator('summary').click();
}

test('the organizer shares an encrypted file and the student decrypts it; students cannot upload', async ({
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
  await expect(
    page.getByRole('heading', { name: 'Room file sharing' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await expect(page.getByLabel('Choose a file (up to 250 MiB)')).toBeVisible();
  await expect(page.getByLabel('Backup passphrase')).not.toBeVisible();
  const invite = await page.locator('.join-link').getAttribute('href');
  expect(invite).toMatch(/#key=[a-f0-9]{64}&access=[A-Za-z0-9_-]+$/);

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
  await expect(participant).toHaveURL(/#key=[a-f0-9]{64}&access=[A-Za-z0-9_-]+$/);
  await participant.getByLabel('Your label').fill('Team Cedar');
  await participant.getByRole('button', { name: 'Request access' }).click();
  await expect(
    participant.getByText(
      'Waiting for organizer approval. This page updates automatically.',
    ),
  ).toBeVisible();
  const memberRow = page
    .getByRole('row')
    .filter({ hasText: 'Team Cedar' });
  await expect(memberRow).toBeVisible();
  await memberRow.getByRole('button', { name: 'Approve', exact: true }).click();
  await participant.getByRole('link', { name: 'Enter room' }).click();
  await expect(
    participant.getByRole('heading', { name: 'Files from your organizer' }),
  ).toBeVisible();
  // Students have no upload control anywhere on the room page.
  await expect(
    participant.getByLabel('Choose a file (up to 250 MiB)'),
  ).toHaveCount(0);
  await expect(
    participant.getByRole('button', { name: /Encrypt and share|Submit file privately/i }),
  ).toHaveCount(0);

  const fixture = {
    name: 'lecture notes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('shared contents no browser other than the student can read'),
  };
  // An interrupted publication must release its pending upload slot.
  const metadataEndpoint = '**/api/rooms/*/files/*/metadata';
  await page.route(metadataEndpoint, (route) => route.fulfill({
    status: 503, contentType: 'application/json',
    body: JSON.stringify({ error: { code: 'UNAVAILABLE', message: 'Upload interrupted.' } }),
  }));
  await page.getByLabel('Choose a file (up to 250 MiB)').setInputFiles(fixture);
  const discarded = page.waitForResponse((response) =>
    response.request().method() === 'DELETE' && /\/files\/[a-f0-9-]+$/.test(new URL(response.url()).pathname));
  await page.getByRole('button', { name: 'Encrypt and share with room' }).click();
  expect((await discarded).status()).toBe(204);
  await expect(page.getByRole('alert')).toHaveText('Upload interrupted.');
  await page.unroute(metadataEndpoint);

  await page.reload();
  await page.getByRole('button', { name: 'Resume upload', exact: true }).click();
  await expect(page.getByText(/Published “lecture notes\.txt”/)).toBeVisible();
  await expect(
    page.getByText(/All approved members can download it/,
    { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Download', exact: true }),
  ).toBeVisible();

  await security(page);
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
    page.getByText(/Restore your organizer backup under Security and recovery/),
  ).toBeVisible();
  await page
    .getByLabel('Backup passphrase')
    .first()
    .fill('a long browser-only backup passphrase');
  await page.getByLabel('Restore key backup (.json)').setInputFiles({
    name: 'recovery.json',
    mimeType: 'application/json',
    buffer: Buffer.from(backupText),
  });
  await expect(
    page.getByText('The organizer key was restored from its backup.'),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Download', exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: '../outputs/Portkey_SharedFiles_Desktop.png',
    fullPage: true,
  });
  await participant.screenshot({
    path: '../outputs/Portkey_SharedFiles_Mobile.png',
    fullPage: true,
  });

  // Recover the participant's own key, which differs from the organizer key.
  await security(participant);
  await participant.getByLabel('Backup passphrase').fill('a long participant recovery passphrase');
  const participantBackupEvent = participant.waitForEvent('download');
  await participant.getByRole('button', { name: 'Download encrypted key backup' }).click();
  const participantBackup = await participantBackupEvent;
  const participantBackupPath = await participantBackup.path();
  const participantBackupText = await (await import('node:fs/promises')).readFile(participantBackupPath!, 'utf8');
  await participant.evaluate(() => new Promise<void>((resolve, reject) => {
    const removal = indexedDB.deleteDatabase('portkey-private-keys');
    removal.onsuccess = () => resolve();
    removal.onerror = () => reject(removal.error);
    removal.onblocked = () => reject(new Error('Key database connection leaked.'));
  }));
  await participant.goto(ownerRoomUrl);
  await expect(participant.getByRole('alert')).toContainText('current invitation');
  await security(participant);
  await participant.getByLabel('Backup passphrase').fill('a long participant recovery passphrase');
  await participant.getByLabel('Restore key backup (.json)').setInputFiles({
    name: 'participant-recovery.json', mimeType: 'application/json', buffer: Buffer.from(participantBackupText),
  });
  await expect(participant.getByText('Your room access was restored.')).toBeVisible();
  await security(participant);
  await expect(participant.getByLabel('Backup passphrase')).toHaveValue('');

  await expect(participant.getByRole('button', { name: 'Rotate encryption key', exact: true })).toHaveCount(0);

  // The student downloads through a mocked save-file picker and retries once
  // against a tampered ciphertext to confirm integrity enforcement.
  await participant.evaluate(() => {
    const target = window as Window & {
      __savedFile?: number[];
      showSaveFilePicker?: (options: unknown) => Promise<unknown>;
    };
    Object.defineProperty(target, 'showSaveFilePicker', {
      configurable: true,
      value: async () => ({
        createWritable: async () =>
          new WritableStream({
            write: (chunk: Uint8Array) => {
              target.__savedFile = [...(target.__savedFile ?? []), ...chunk];
            },
          }),
      }),
    });
  });
  await participant
    .getByRole('button', { name: 'Refresh files' })
    .click();
  await expect(
    participant.getByRole('button', { name: 'Download', exact: true }),
  ).toBeVisible();
  const participantChunks = '**/rooms/*/files/*/chunks/*';
  await participant.route(participantChunks, async (route) => {
    const response = await route.fetch();
    const body = Buffer.from(await response.body());
    body[0] ^= 0xff;
    await route.fulfill({ response, body });
  });
  await participant.getByRole('button', { name: 'Download', exact: true }).click();
  await expect(participant.getByRole('alert')).toContainText(
    /integrity|manifest|authenticate/i,
  );
  expect(
    await participant.evaluate(
      () => (window as Window & { __savedFile?: number[] }).__savedFile,
    ),
  ).toBeUndefined();
  await participant.unroute(participantChunks);
  await participant
    .getByRole('button', { name: 'Download', exact: true })
    .click();
  await expect
    .poll(() =>
      participant.evaluate(
        () => (window as Window & { __savedFile?: number[] }).__savedFile,
      ),
    )
    .toEqual(Array.from(fixture.buffer));
  await participant.evaluate(() =>
    Object.defineProperty(window, 'showSaveFilePicker', {
      configurable: true,
      value: undefined,
    }),
  );
  await participant
    .getByRole('button', { name: 'Remove local download copies' })
    .click();

  // Nothing readable ever crossed the network: no plaintext and no filename.
  for (const body of transferred) {
    expect(body.includes(fixture.buffer)).toBe(false);
    expect(body.includes(Buffer.from(fixture.name))).toBe(false);
    expect(
      body.includes(Buffer.from('a long browser-only backup passphrase')),
    ).toBe(false);
  }

  // A mismatched simulated room key blocks file sharing and hides the invite
  // fingerprint until the real registration returns.
  const fake = await page.evaluate(async () => {
    const moduleUrl = '/client/roomCrypto.ts';
    const cryptoModule = await import(moduleUrl);
    const pair = await cryptoModule.createKey();
    return {
      ownerPublicKey: cryptoModule.encodeBase64(pair.publicKey),
      ownerFingerprint: pair.fingerprint,
    };
  });
  await page.route('**/api' + ownerRoomPath + '/files/keys', (route) =>
    route.fulfill({ json: fake }),
  );
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('Restore your organizer backup');
  await expect(page.locator('.join-link')).toHaveCount(0);
  await page.unroute('**/api' + ownerRoomPath + '/files/keys');
  await page.reload();
  await expect(page.locator('.join-link')).toHaveAttribute(
    'href',
    /#key=[a-f0-9]{64}&access=[A-Za-z0-9_-]+$/,
  );

  // Room access is verified silently; an unrelated invitation key is rejected.
  const wrongAccess = await participant.evaluate(async () => {
    const url = '/client/roomCrypto.ts'; const c = await import(url);
    return c.encodeRoomAccess(await c.createKey());
  });
  await participant.goto(ownerRoomUrl + '#access=' + wrongAccess);
  await expect(participant.getByRole('alert')).toContainText('current invitation');
  await expect(participant.getByRole('button', { name: 'Download', exact: true })).toHaveCount(0);
  // A previously accepted invitation is retained in this browser without a
  // fingerprint confirmation or key-rotation step on later visits.
  await participant.goto(ownerRoomUrl);
  await expect(participant.getByRole('button', { name: 'Download', exact: true })).toBeVisible();
  await expect(participant.getByText('Organizer verification fingerprint:', { exact: false })).not.toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page
      .locator('.room-files')
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

test('browser crypto binds rooms, recipients and chunks, and protects backup keys', async ({
  page,
}) => {
  await page.goto('/');
  const result = await page.evaluate(async () => {
    const moduleUrl = '/client/roomCrypto.ts';
    const c = await import(moduleUrl);
    const room = crypto.randomUUID();
    const id = crypto.randomUUID();
    const organizer = await c.createKey();
    const student = await c.createKey();
    const file = new File([new Uint8Array(1048577).fill(43)], 'two chunks.bin');
    const plan = await c.prepareDistribution(
      file,
      room,
      id,
      [
        { id: organizer.fingerprint, publicKey: organizer.publicKey },
        { id: student.fingerprint, publicKey: student.publicKey },
      ],
    );
    const firstChunk = await c.encryptDistributionChunk(plan, 0);
    const secondChunk = await c.encryptDistributionChunk(plan, 1);
    const digestOf = async (value: Uint8Array) => await c.digest(value);
    const manifest = await c.distributionManifest(plan, [
      await digestOf(firstChunk.ciphertext),
      await digestOf(secondChunk.ciphertext),
    ]);
    const failures: string[] = [];
    async function mustReject(label: string, work: () => Promise<unknown>) {
      try {
        await work();
        failures.push(label);
      } catch {}
    }
    const context = (
      roomId: string,
      purpose = 'submission-file-key',
      fingerprint = organizer.fingerprint,
    ) =>
      new TextEncoder().encode(
        JSON.stringify({
          protocol: 'portkey-private-submission-v1',
          roomId,
          objectId: id,
          recipientFingerprint: fingerprint,
          purpose,
        }),
      );
    const studentEnvelope = plan.envelopes.find(
      (envelope: { recipientId: string }) =>
        envelope.recipientId === student.fingerprint,
    )!;
    const key = await c.hpkeOpen(
      { ...student, publicKey: student.publicKey },
      { enc: studentEnvelope.enc, ciphertext: studentEnvelope.ciphertext },
      context(room, 'submission-file-key', student.fingerprint),
    );
    const organizerEnvelope = plan.envelopes.find(
      (envelope: { recipientId: string }) =>
        envelope.recipientId === organizer.fingerprint,
    )!;
    const organizerKey = await c.hpkeOpen(
      organizer,
      { enc: organizerEnvelope.enc, ciphertext: organizerEnvelope.ciphertext },
      context(room, 'submission-file-key'),
    );
    await mustReject('room substitution', () =>
      c.hpkeOpen(
        organizer,
        {
          enc: organizerEnvelope.enc,
          ciphertext: organizerEnvelope.ciphertext,
        },
        context(crypto.randomUUID()),
      ),
    );
    await mustReject('purpose substitution', () =>
      c.hpkeOpen(
        organizer,
        {
          enc: organizerEnvelope.enc,
          ciphertext: organizerEnvelope.ciphertext,
        },
        context(room, 'another-purpose'),
      ),
    );
    await mustReject('recipient substitution', () =>
      c.hpkeOpen(
        student,
        {
          enc: organizerEnvelope.enc,
          ciphertext: organizerEnvelope.ciphertext,
        },
        context(room),
      ),
    );
    const descriptor = await c.decryptDescriptor(plan.descriptor, key, room, id);
    const plain = await c.decryptChunk(
      firstChunk.ciphertext,
      key,
      descriptor.keySalt,
      descriptor.noncePrefix,
      room,
      id,
      0,
      descriptor.chunkSizes[0],
    );
    await mustReject('chunk reordering', () =>
      c.decryptChunk(
        firstChunk.ciphertext,
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
        firstChunk.ciphertext.slice(0, -1),
        key,
        descriptor.keySalt,
        descriptor.noncePrefix,
        room,
        id,
        0,
        descriptor.chunkSizes[0],
      ),
    );
    const altered = Uint8Array.from(firstChunk.ciphertext);
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
    const envelopeBytes = c.decodeBase64(studentEnvelope.ciphertext);
    envelopeBytes[0] ^= 1;
    await mustReject('envelope modification', () =>
      c.hpkeOpen(
        student,
        {
          enc: studentEnvelope.enc,
          ciphertext: c.encodeBase64(envelopeBytes),
        },
        context(room),
      ),
    );
    const password = 'a long unique testing backup passphrase';
    const backup = await c.exportEncryptedBackup(room, organizer, password);
    await mustReject('wrong backup password', () =>
      c.restoreEncryptedBackup(
        room,
        backup,
        'a different long testing password',
        organizer.fingerprint,
      ),
    );
    await mustReject('wrong room backup', () =>
      c.restoreEncryptedBackup(
        crypto.randomUUID(),
        backup,
        password,
        organizer.fingerprint,
      ),
    );
    await mustReject('wrong registered key', () =>
      c.restoreEncryptedBackup(room, backup, password, student.fingerprint),
    );
    const restored = await c.restoreEncryptedBackup(
      room,
      backup,
      password,
      organizer.fingerprint,
    );
    await mustReject('local key overwrite', () =>
      c.retainConfirmedKey(room, student),
    );
    const saved = await c.loadKey(room);
    const emptyId = crypto.randomUUID();
    const emptyPlan = await c.prepareDistribution(
      new File([], 'empty.txt'),
      room,
      emptyId,
      [{ id: student.fingerprint, publicKey: student.publicKey }],
    );
    const emptyChunk = await c.encryptDistributionChunk(emptyPlan, 0);
    const emptyPlain = await c.decryptChunk(
      emptyChunk.ciphertext,
      emptyPlan.fileKey,
      emptyPlan.keySalt,
      emptyPlan.noncePrefix,
      room,
      emptyId,
      0,
      emptyPlan.chunkSizes[0],
    );
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
      secondLength: secondChunk.ciphertext.length,
      restored:
        restored.fingerprint === organizer.fingerprint &&
        saved?.fingerprint === organizer.fingerprint,
      organizerOpens: organizerKey.length === 32,
      emptyLength: emptyPlain.length,
      manifestMatches: manifest.length === 64,
    };
  });
  expect(result).toEqual({
    failures: [],
    plainLength: 1048576,
    secondLength: 17,
    restored: true,
    organizerOpens: true,
    emptyLength: 0,
    manifestMatches: true,
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
  await page
    .getByRole('navigation', { name: 'Workspace' })
    .getByRole('link', { name: 'Your rooms', exact: true })
    .click();
  await page.getByLabel('Room title').fill('Design sprint');
  await page
    .getByLabel('Public description')
    .fill('A new brief for the next event');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  await page
    .getByRole('navigation', { name: 'Workspace' })
    .getByRole('link', { name: 'Your rooms', exact: true })
    .click();

  const rooms = page.locator('.rooms-list > li');
  await expect(rooms).toHaveCount(2);
  await page.getByLabel('Search rooms').fill('lighting');
  await expect(rooms).toHaveCount(1);
  await expect(rooms.first()).toContainText('Photography basics');
  await page.getByLabel('Filter rooms by status').selectOption('draft');
  await expect(
    page.getByRole('heading', { name: 'No matching rooms' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Clear the filters' }).click();
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
      name: 'Use Photography basics as a template',
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
  await page
    .getByRole('navigation', { name: 'Workspace' })
    .getByRole('link', { name: 'Your rooms', exact: true })
    .click();
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
