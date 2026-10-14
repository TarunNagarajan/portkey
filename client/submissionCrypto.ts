import {
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from '@hpke/core';
import { z } from 'zod';

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const DB_NAME = 'portkey-private-keys';
const KEY_STORE = 'room-keys';
const UPLOAD_STORE = 'uploads';
const PROTOCOL = 'portkey-private-submission-v1';
const bufferSource = (value: Uint8Array): ArrayBuffer =>
  Uint8Array.from(value).buffer;

export interface RecipientKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fingerprint: string;
}
export interface Envelope {
  enc: string;
  ciphertext: string;
}

const bytes = (value: ArrayBuffer | ArrayBufferView) =>
  value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
const base64 = (value: Uint8Array) => btoa(String.fromCharCode(...value));
const unbase64 = (value: string) =>
  Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
const concat = (...parts: Uint8Array[]) => {
  const result = new Uint8Array(
    parts.reduce((total, part) => total + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const opening = indexedDB.open(DB_NAME, 2);
    opening.onupgradeneeded = () => {
      if (!opening.result.objectStoreNames.contains(KEY_STORE))
        opening.result.createObjectStore(KEY_STORE);
      if (!opening.result.objectStoreNames.contains(UPLOAD_STORE))
        opening.result.createObjectStore(UPLOAD_STORE);
    };
    opening.onsuccess = () => resolve(opening.result);
    opening.onerror = () => reject(opening.error);
  });
}

async function storeKey(roomId: string, value: RecipientKeyPair) {
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, 'readwrite');
    tx.objectStore(KEY_STORE).add(
      {
        publicKey: base64(value.publicKey),
        privateKey: base64(value.privateKey),
        fingerprint: value.fingerprint,
      },
      roomId,
    );
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () =>
      reject(
        tx.error ?? new Error('Local browser storage transaction was aborted.'),
      );
  }).finally(() => db.close());
}

export async function loadKey(
  roomId: string,
): Promise<RecipientKeyPair | null> {
  const db = await database();
  const value = await new Promise<
    { publicKey: string; privateKey: string; fingerprint: string } | undefined
  >((resolve, reject) => {
    const request = db
      .transaction(KEY_STORE)
      .objectStore(KEY_STORE)
      .get(roomId);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  }).finally(() => db.close());
  return value
    ? {
        publicKey: unbase64(value.publicKey),
        privateKey: unbase64(value.privateKey),
        fingerprint: value.fingerprint,
      }
    : null;
}

export async function createKey(): Promise<RecipientKeyPair> {
  const pair = await suite.kem.generateKeyPair();
  const publicKey = bytes(await suite.kem.serializePublicKey(pair.publicKey));
  const privateKey = bytes(
    await suite.kem.serializePrivateKey(pair.privateKey),
  );
  const value = { publicKey, privateKey, fingerprint: await digest(publicKey) };
  return value;
}

export async function retainConfirmedKey(
  roomId: string,
  value: RecipientKeyPair,
) {
  try {
    await storeKey(roomId, value);
  } catch {
    const current = await loadKey(roomId);
    if (
      !current ||
      current.fingerprint !== value.fingerprint ||
      base64(current.publicKey) !== base64(value.publicKey) ||
      base64(current.privateKey) !== base64(value.privateKey)
    )
      throw new Error(
        'A different key is already stored for this room. Restore its backup before continuing.',
      );
  }
}

export const retainPendingKey = retainConfirmedKey;

export interface UploadPlan {
  roomId: string;
  objectId: string;
  fileSize: number;
  chunkSizes: number[];
  sourceDigests: (string | null)[];
  cipherDigests: (string | null)[];
  chunkStates: ('new' | 'encrypting' | 'sealed')[];
  fileKey: string;
  keySalt: string;
  noncePrefix: string;
  descriptor: string;
  ownerEnvelope: Envelope;
  submitterEnvelope: Envelope;
}

const uploadPlanSchema = z
  .object({
    roomId: z.string().uuid(),
    objectId: z.string().uuid(),
    fileSize: z.number().int().min(0).max(262144000),
    chunkSizes: z.array(z.number().int().min(0).max(1048576)).min(1).max(250),
    sourceDigests: z
      .array(
        z
          .string()
          .regex(/^[a-f0-9]{64}$/)
          .nullable(),
      )
      .max(250),
    cipherDigests: z
      .array(
        z
          .string()
          .regex(/^[a-f0-9]{64}$/)
          .nullable(),
      )
      .max(250),
    chunkStates: z.array(z.enum(['new', 'encrypting', 'sealed'])).max(250),
    fileKey: z.string().max(100),
    keySalt: z.string().max(100),
    noncePrefix: z.string().max(50),
    descriptor: z.string().max(22000),
    ownerEnvelope: z.object({
      enc: z.string().max(100),
      ciphertext: z.string().max(500),
    }),
    submitterEnvelope: z.object({
      enc: z.string().max(100),
      ciphertext: z.string().max(500),
    }),
  })
  .strict();

async function saveUploadPlan(plan: UploadPlan) {
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(UPLOAD_STORE, 'readwrite');
    tx.objectStore(UPLOAD_STORE).put(plan, `plan:${plan.objectId}`);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () =>
      reject(
        tx.error ?? new Error('Local browser storage transaction was aborted.'),
      );
  }).finally(() => db.close());
}

export async function loadUploadPlans(roomId: string) {
  const db = await database();
  const plans = await new Promise<UploadPlan[]>((resolve, reject) => {
    const values: UploadPlan[] = [];
    const tx = db.transaction(UPLOAD_STORE);
    const request = tx.objectStore(UPLOAD_STORE).openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      if (String(cursor.key).startsWith('plan:')) {
        const parsed = uploadPlanSchema.safeParse(cursor.value);
        if (parsed.success && parsed.data.roomId === roomId)
          values.push(parsed.data);
      }
      cursor.continue();
    };
    tx.oncomplete = () => resolve(values);
    request.onerror = () => reject(request.error);
  }).finally(() => db.close());
  return plans;
}

async function loadCipherChunk(
  objectId: string,
  index: number,
): Promise<{
  ciphertext: Uint8Array;
  sourceDigest: string;
  cipherDigest: string;
} | null> {
  const db = await database();
  const value = await new Promise<
    | { ciphertext: ArrayBuffer; sourceDigest: string; cipherDigest: string }
    | undefined
  >((resolve, reject) => {
    const request = db
      .transaction(UPLOAD_STORE)
      .objectStore(UPLOAD_STORE)
      .get(`chunk:${objectId}:${index}`);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  }).finally(() => db.close());
  return value
    ? {
        ciphertext: new Uint8Array(value.ciphertext),
        sourceDigest: value.sourceDigest,
        cipherDigest: value.cipherDigest,
      }
    : null;
}

async function reserveChunk(
  objectId: string,
  index: number,
  sourceDigest: string,
): Promise<'reserved' | 'sealed' | 'lost'> {
  const db = await database();
  let result: 'reserved' | 'sealed' | 'lost' = 'lost';
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(UPLOAD_STORE, 'readwrite');
    const store = tx.objectStore(UPLOAD_STORE);
    const request = store.get(`plan:${objectId}`);
    request.onsuccess = () => {
      const parsed = uploadPlanSchema.safeParse(request.result);
      if (!parsed.success) {
        tx.abort();
        return;
      }
      const plan = parsed.data;
      if (plan.sourceDigests[index] !== sourceDigest) {
        result = 'lost';
        tx.abort();
        return;
      }
      if (plan.chunkStates[index] === 'sealed') {
        result = 'sealed';
        return;
      }
      if (plan.chunkStates[index] === 'encrypting') {
        result = 'lost';
        tx.abort();
        return;
      }
      plan.sourceDigests[index] = sourceDigest;
      plan.chunkStates[index] = 'encrypting';
      store.put(plan, `plan:${objectId}`);
      result = 'reserved';
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => resolve();
  }).finally(() => db.close());
  return result;
}

async function saveCipherChunk(
  objectId: string,
  index: number,
  ciphertext: Uint8Array,
  sourceDigest: string,
  cipherDigest: string,
) {
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(UPLOAD_STORE, 'readwrite');
    const store = tx.objectStore(UPLOAD_STORE);
    const request = store.get(`plan:${objectId}`);
    request.onsuccess = () => {
      const parsed = uploadPlanSchema.safeParse(request.result);
      if (
        !parsed.success ||
        parsed.data.chunkStates[index] !== 'encrypting' ||
        parsed.data.sourceDigests[index] !== sourceDigest
      ) {
        tx.abort();
        return;
      }
      const plan = parsed.data;
      plan.chunkStates[index] = 'sealed';
      plan.cipherDigests[index] = cipherDigest;
      store.put(plan, `plan:${objectId}`);
      store.add(
        { ciphertext: bufferSource(ciphertext), sourceDigest, cipherDigest },
        `chunk:${objectId}:${index}`,
      );
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () =>
      reject(
        tx.error ?? new Error('Local browser storage transaction was aborted.'),
      );
  }).finally(() => db.close());
}

export async function clearUpload(objectId: string) {
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(UPLOAD_STORE, 'readwrite');
    const store = tx.objectStore(UPLOAD_STORE);
    const request = store.openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      if (
        String(cursor.key) === `plan:${objectId}` ||
        String(cursor.key).startsWith(`chunk:${objectId}:`)
      )
        cursor.delete();
      cursor.continue();
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () =>
      reject(
        tx.error ?? new Error('Local browser storage transaction was aborted.'),
      );
  }).finally(() => db.close());
}

export async function digest(value: Uint8Array) {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(value))),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('');
}

export async function hpkeSeal(
  publicKey: Uint8Array,
  value: Uint8Array,
  info: Uint8Array,
) {
  const key = await suite.kem.deserializePublicKey(publicKey);
  const sender = await suite.createSenderContext({
    recipientPublicKey: key,
    info,
  });
  return {
    enc: bytes(sender.enc),
    ciphertext: bytes(await sender.seal(value, info)),
  };
}

export async function hpkeOpen(
  pair: RecipientKeyPair,
  envelope: Envelope,
  info: Uint8Array,
) {
  const privateKey = await suite.kem.deserializePrivateKey(pair.privateKey);
  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: unbase64(envelope.enc),
    info,
  });
  return bytes(await recipient.open(unbase64(envelope.ciphertext), info));
}

const keyContext = (
  roomId: string,
  objectId: string,
  fingerprint: string,
  purpose: string,
) =>
  encoder.encode(
    JSON.stringify({
      protocol: PROTOCOL,
      roomId,
      objectId,
      recipientFingerprint: fingerprint,
      purpose,
    }),
  );

async function deriveAes(raw: Uint8Array, salt: Uint8Array, label: string) {
  const material = await crypto.subtle.importKey(
    'raw',
    bufferSource(raw),
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: bufferSource(salt),
      info: bufferSource(encoder.encode(`${PROTOCOL}:${label}`)),
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function chunkNonce(prefix: Uint8Array, index: number) {
  const nonce = new Uint8Array(12);
  nonce.set(prefix);
  new DataView(nonce.buffer).setUint32(8, index, false);
  return nonce;
}

function chunkContext(
  roomId: string,
  objectId: string,
  index: number,
  plainLength: number,
) {
  return encoder.encode(
    JSON.stringify({
      protocol: PROTOCOL,
      roomId,
      objectId,
      purpose: 'content-chunk',
      index,
      plainLength,
    }),
  );
}

export async function prepareSubmission(
  file: File,
  roomId: string,
  objectId: string,
  ownerPublic: Uint8Array,
  ownerFingerprint: string,
  submitter: RecipientKeyPair,
): Promise<UploadPlan> {
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const keySalt = crypto.getRandomValues(new Uint8Array(32));
  const noncePrefix = crypto.getRandomValues(new Uint8Array(8));
  const metadataNonce = crypto.getRandomValues(new Uint8Array(12));
  const metadataKey = await deriveAes(fileKey, keySalt, 'metadata');
  const count = Math.max(1, Math.ceil(file.size / (1024 * 1024)));
  if (count > 250)
    throw new Error('The file exceeds the 250 MiB upload limit.');
  const sizes = Array.from({ length: count }, (_, index) =>
    Math.max(0, Math.min(1024 * 1024, file.size - index * 1024 * 1024)),
  );
  const sourceDigests: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const part = new Uint8Array(
      await file
        .slice(index * 1024 * 1024, index * 1024 * 1024 + sizes[index])
        .arrayBuffer(),
    );
    if (part.length !== sizes[index])
      throw new Error('The source file could not be read completely.');
    sourceDigests.push(await digest(part));
  }
  const descriptor = {
    protocol: PROTOCOL,
    filename: file.name,
    mediaType: file.type || 'application/octet-stream',
    size: file.size,
    chunkSizes: sizes,
    keySalt: base64(keySalt),
    noncePrefix: base64(noncePrefix),
    metadataNonce: base64(metadataNonce),
  };
  const metadataAad = encoder.encode(
    JSON.stringify({
      protocol: PROTOCOL,
      roomId,
      objectId,
      purpose: 'encrypted-descriptor',
    }),
  );
  const encryptedDescriptor = bytes(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: metadataNonce,
        additionalData: metadataAad,
        tagLength: 128,
      },
      metadataKey,
      encoder.encode(JSON.stringify(descriptor)),
    ),
  );
  const keyBytes = fileKey;
  const ownerInfo = keyContext(
    roomId,
    objectId,
    ownerFingerprint,
    'submission-file-key',
  );
  const submitterInfo = keyContext(
    roomId,
    objectId,
    submitter.fingerprint,
    'submission-file-key',
  );
  const [ownerEnvelope, submitterEnvelope] = await Promise.all([
    hpkeSeal(ownerPublic, keyBytes, ownerInfo),
    hpkeSeal(submitter.publicKey, keyBytes, submitterInfo),
  ]);
  const plan: UploadPlan = {
    roomId,
    objectId,
    fileSize: file.size,
    chunkSizes: sizes,
    sourceDigests,
    cipherDigests: sizes.map(() => null),
    chunkStates: sizes.map(() => 'new'),
    fileKey: base64(fileKey),
    keySalt: base64(keySalt),
    noncePrefix: base64(noncePrefix),
    descriptor: base64(
      concat(
        new Uint8Array([1]),
        keySalt,
        noncePrefix,
        metadataNonce,
        encryptedDescriptor,
      ),
    ),
    ownerEnvelope: {
      enc: base64(ownerEnvelope.enc),
      ciphertext: base64(ownerEnvelope.ciphertext),
    },
    submitterEnvelope: {
      enc: base64(submitterEnvelope.enc),
      ciphertext: base64(submitterEnvelope.ciphertext),
    },
  };
  await saveUploadPlan(plan);
  return plan;
}

export async function encryptUploadChunk(
  file: File | null,
  plan: UploadPlan,
  index: number,
) {
  const cached = await loadCipherChunk(plan.objectId, index);
  if (cached) {
    if (file) {
      const expectedLength = plan.chunkSizes[index];
      const source = new Uint8Array(
        await file
          .slice(index * 1024 * 1024, index * 1024 * 1024 + expectedLength)
          .arrayBuffer(),
      );
      if ((await digest(source)) !== cached.sourceDigest)
        throw new Error(
          'The selected file differs from the interrupted upload. Start a new upload to use this file.',
        );
    }
    return cached.ciphertext;
  }
  if (!file)
    throw new Error(
      'Choose the original file to continue this interrupted upload.',
    );
  if (file.size !== plan.fileSize)
    throw new Error(
      'The selected file size does not match the interrupted upload.',
    );
  const plainLength = plan.chunkSizes[index];
  const plaintext = new Uint8Array(
    await file
      .slice(index * 1024 * 1024, index * 1024 * 1024 + plainLength)
      .arrayBuffer(),
  );
  if (plaintext.length !== plainLength)
    throw new Error('The selected file could not be read completely.');
  const sourceDigest = await digest(plaintext);
  const reservation = await reserveChunk(plan.objectId, index, sourceDigest);
  if (reservation === 'sealed') {
    const sealed = await loadCipherChunk(plan.objectId, index);
    if (!sealed || sealed.sourceDigest !== sourceDigest)
      throw new Error(
        'The sealed encrypted chunk is missing or belongs to another file. Start a new upload.',
      );
    return sealed.ciphertext;
  }
  if (reservation !== 'reserved')
    throw new Error(
      'This chunk was already reserved for encryption but its immutable ciphertext is missing. Start a new upload.',
    );
  const contentKey = await deriveAes(
    unbase64(plan.fileKey),
    unbase64(plan.keySalt),
    'content',
  );
  const ciphertext = bytes(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: bufferSource(chunkNonce(unbase64(plan.noncePrefix), index)),
        additionalData: bufferSource(
          chunkContext(plan.roomId, plan.objectId, index, plaintext.length),
        ),
        tagLength: 128,
      },
      contentKey,
      bufferSource(plaintext),
    ),
  );
  await saveCipherChunk(
    plan.objectId,
    index,
    ciphertext,
    sourceDigest,
    await digest(ciphertext),
  );
  return ciphertext;
}

export async function uploadManifest(plan: UploadPlan) {
  const hashes: Uint8Array[] = [];
  for (let index = 0; index < plan.chunkSizes.length; index += 1) {
    const chunk = await loadCipherChunk(plan.objectId, index);
    if (!chunk)
      throw new Error(
        'An encrypted chunk is missing from the local retry store.',
      );
    hashes.push(
      Uint8Array.from(chunk.cipherDigest.match(/../g) ?? [], (value) =>
        Number.parseInt(value, 16),
      ),
    );
  }
  return digest(concat(unbase64(plan.descriptor), ...hashes));
}

export async function decryptDescriptor(
  encrypted: string,
  fileKey: Uint8Array,
  roomId: string,
  objectId: string,
) {
  const packet = unbase64(encrypted);
  if (packet[0] !== 1 || packet.length < 69)
    throw new Error('Encrypted file format is not supported.');
  const keySaltBytes = packet.slice(1, 33);
  const noncePrefix = packet.slice(33, 41);
  const nonce = packet.slice(41, 53);
  const ciphertext = packet.slice(53);
  const keySalt = base64(keySaltBytes);
  const key = await deriveAes(fileKey, keySaltBytes, 'metadata');
  const aad = encoder.encode(
    JSON.stringify({
      protocol: PROTOCOL,
      roomId,
      objectId,
      purpose: 'encrypted-descriptor',
    }),
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    key,
    ciphertext,
  );
  const value = z
    .object({
      protocol: z.literal(PROTOCOL),
      filename: z.string().min(1).max(255),
      mediaType: z.string().min(1).max(127),
      size: z.number().int().min(0).max(262144000),
      chunkSizes: z.array(z.number().int().min(0).max(1048576)).min(1).max(250),
      keySalt: z.string().max(100),
      noncePrefix: z.string().max(50),
      metadataNonce: z.string().max(50),
    })
    .strict()
    .parse(JSON.parse(decoder.decode(plaintext)));
  if (
    value.protocol !== PROTOCOL ||
    value.keySalt !== keySalt ||
    value.noncePrefix !== base64(noncePrefix) ||
    value.metadataNonce !== base64(nonce)
  )
    throw new Error('Encrypted file metadata did not authenticate.');
  if (
    value.chunkSizes.reduce((total, size) => total + size, 0) !== value.size ||
    value.chunkSizes.length !== Math.max(1, Math.ceil(value.size / 1048576))
  )
    throw new Error('Encrypted file metadata has invalid size boundaries.');
  return value;
}

export async function decryptChunk(
  ciphertext: Uint8Array,
  fileKey: Uint8Array,
  keySalt: string,
  noncePrefix: string,
  roomId: string,
  objectId: string,
  index: number,
  plainLength: number,
) {
  const key = await deriveAes(fileKey, unbase64(keySalt), 'content');
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: bufferSource(chunkNonce(unbase64(noncePrefix), index)),
      additionalData: bufferSource(
        chunkContext(roomId, objectId, index, plainLength),
      ),
      tagLength: 128,
    },
    key,
    bufferSource(ciphertext),
  );
  return bytes(plaintext);
}

function safeFilename(value: string) {
  return (
    value
      .replace(/[\\/\u0000-\u001f]/g, '_')
      .replace(/[^\p{L}\p{N} ._()-]/gu, '_')
      .slice(0, 255) || 'submission'
  );
}

type CipherChunkReader = (
  index: number,
) => Promise<{ bytes: Uint8Array; sha256: string }>;

type DownloadDirectory = FileSystemDirectoryHandle & {
  entries(): AsyncIterableIterator<[string, FileSystemHandle]>;
};
const localDownloadUrls = new Map<string, string>();

async function downloadDirectory() {
  const storage = navigator.storage as StorageManager & {
    getDirectory?: () => Promise<FileSystemDirectoryHandle>;
  };
  if (!storage.getDirectory) return null;
  return (await (
    await storage.getDirectory()
  ).getDirectoryHandle('portkey-verified-downloads', {
    create: true,
  })) as DownloadDirectory;
}

export async function clearLocalDownloadCopies() {
  const directory = await downloadDirectory();
  if (!directory) return 0;
  let removed = 0;
  for await (const [name] of directory.entries()) {
    if (!/^portkey-[a-f0-9-]{36}\.tmp$/.test(name)) continue;
    await directory.removeEntry(name);
    const url = localDownloadUrls.get(name);
    if (url) URL.revokeObjectURL(url);
    localDownloadUrls.delete(name);
    removed += 1;
  }
  return removed;
}

export async function decryptSubmissionToDownload(
  roomId: string,
  submission: {
    id: string;
    descriptor: string;
    envelope: Envelope;
    chunkCount: number;
    manifestSha256: string;
  },
  pair: RecipientKeyPair,
  readCipherChunk: CipherChunkReader,
  onProgress: (read: number, total: number) => void,
) {
  const info = keyContext(
    roomId,
    submission.id,
    pair.fingerprint,
    'submission-file-key',
  );
  const fileKey = await hpkeOpen(pair, submission.envelope, info);
  if (fileKey.length !== 32)
    throw new Error('The encrypted file key has an invalid length.');
  const descriptor = await decryptDescriptor(
    submission.descriptor,
    fileKey,
    roomId,
    submission.id,
  );
  if (descriptor.chunkSizes.length !== submission.chunkCount)
    throw new Error(
      'The encrypted file manifest has the wrong number of chunks.',
    );
  const picker = (
    window as Window & {
      showSaveFilePicker?: (options: {
        suggestedName: string;
      }) => Promise<FileSystemFileHandle>;
    }
  ).showSaveFilePicker;
  const opfs = await downloadDirectory();
  if (opfs) {
    let copies = 0;
    for await (const [name] of opfs.entries())
      if (/^portkey-[a-f0-9-]{36}\.tmp$/.test(name)) copies += 1;
    if (copies >= 5)
      throw new Error(
        'Remove local download copies before starting another download.',
      );
  }
  if (!opfs && descriptor.size > 50 * 1024 * 1024)
    throw new Error(
      'This browser supports downloads up to 50 MiB. Use a browser with private temporary storage for larger files.',
    );
  const target =
    picker && opfs
      ? await picker({ suggestedName: safeFilename(descriptor.filename) })
      : null;
  const tempName = `portkey-${crypto.randomUUID()}.tmp`;
  const tempHandle = opfs
    ? await opfs.getFileHandle(tempName, { create: true })
    : null;
  const tempWriter = tempHandle ? await tempHandle.createWritable() : null;
  const fallbackParts: Uint8Array[] = [];
  const hashes: Uint8Array[] = [];
  let total = 0;
  let keepLocalCopy = false;
  try {
    for (let index = 0; index < submission.chunkCount; index += 1) {
      const chunk = await readCipherChunk(index);
      const actualDigest = await digest(chunk.bytes);
      if (actualDigest !== chunk.sha256)
        throw new Error(
          'A downloaded encrypted chunk failed its integrity check.',
        );
      hashes.push(
        Uint8Array.from(actualDigest.match(/../g) ?? [], (value) =>
          Number.parseInt(value, 16),
        ),
      );
      const plaintext = await decryptChunk(
        chunk.bytes,
        fileKey,
        descriptor.keySalt,
        descriptor.noncePrefix,
        roomId,
        submission.id,
        index,
        descriptor.chunkSizes[index],
      );
      total += plaintext.length;
      if (tempWriter) await tempWriter.write(bufferSource(plaintext));
      else fallbackParts.push(plaintext);
      onProgress(total, descriptor.size);
    }
    const manifest = await digest(
      concat(decodeBase64(submission.descriptor), ...hashes),
    );
    if (total !== descriptor.size || manifest !== submission.manifestSha256)
      throw new Error(
        'The downloaded file does not match its authenticated manifest.',
      );
    if (tempWriter) {
      await tempWriter.close();
      const staged = await tempHandle!.getFile();
      if (staged.size !== descriptor.size)
        throw new Error('The staged decrypted file has the wrong size.');
      if (target) {
        const output = await target.createWritable();
        await staged.stream().pipeTo(output);
      } else {
        const blob = new Blob([staged], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        localDownloadUrls.set(tempName, url);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = safeFilename(descriptor.filename);
        anchor.click();
        keepLocalCopy = true;
      }
    } else {
      const blob = new Blob(
        fallbackParts.map((part) => bufferSource(part)),
        { type: 'application/octet-stream' },
      );
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = safeFilename(descriptor.filename);
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }
  } catch (error) {
    if (tempWriter) await tempWriter.abort().catch(() => undefined);
    throw error;
  } finally {
    if (opfs && tempHandle && !keepLocalCopy)
      await opfs.removeEntry(tempName).catch(() => undefined);
  }
}

export async function exportEncryptedBackup(
  roomId: string,
  pair: RecipientKeyPair,
  password: string,
) {
  if (password.length < 12 || password.length > 256)
    throw new Error('Use a backup passphrase between 12 and 256 characters.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const plaintext = encoder.encode(
    JSON.stringify({
      version: 1,
      roomId,
      publicKey: base64(pair.publicKey),
      privateKey: base64(pair.privateKey),
      fingerprint: pair.fingerprint,
    }),
  );
  const aad = encoder.encode('portkey-key-backup-v1');
  const ciphertext = bytes(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      plaintext,
    ),
  );
  return JSON.stringify(
    {
      format: 'portkey-key-backup-v1',
      salt: base64(salt),
      nonce: base64(nonce),
      ciphertext: base64(ciphertext),
    },
    null,
    2,
  );
}

export async function restoreEncryptedBackup(
  roomId: string,
  backupText: string,
  password: string,
  expectedFingerprint: string,
) {
  if (
    backupText.length > 32_768 ||
    password.length < 12 ||
    password.length > 256
  )
    throw new Error('Backup or passphrase is too large or invalid.');
  const backup = z
    .object({
      format: z.literal('portkey-key-backup-v1'),
      salt: z.string().max(100),
      nonce: z.string().max(50),
      ciphertext: z.string().max(20_000),
    })
    .strict()
    .parse(JSON.parse(backupText));
  const salt = unbase64(backup.salt);
  const nonce = unbase64(backup.nonce);
  const ciphertext = unbase64(backup.ciphertext);
  if (
    salt.length !== 16 ||
    nonce.length !== 12 ||
    ciphertext.length < 16 ||
    ciphertext.length > 2048
  )
    throw new Error('The encrypted backup has invalid bounds.');
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: bufferSource(salt),
      iterations: 600_000,
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: bufferSource(nonce),
      additionalData: encoder.encode('portkey-key-backup-v1'),
    },
    key,
    bufferSource(ciphertext),
  );
  const value = z
    .object({
      version: z.literal(1),
      roomId: z.string().uuid(),
      publicKey: z.string().max(200),
      privateKey: z.string().max(700),
      fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .strict()
    .parse(JSON.parse(decoder.decode(plaintext)));
  const pair = {
    publicKey: unbase64(value.publicKey),
    privateKey: unbase64(value.privateKey),
    fingerprint: value.fingerprint,
  };
  if (pair.publicKey.length !== 65 || pair.privateKey.length !== 32)
    throw new Error('The key backup contents have invalid bounds.');
  if (
    value.version !== 1 ||
    value.roomId !== roomId ||
    pair.fingerprint !== expectedFingerprint ||
    (await digest(pair.publicKey)) !== expectedFingerprint
  )
    throw new Error('The backup key does not match this room’s pinned key.');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const context = encoder.encode(
    `backup-restore:${roomId}:${expectedFingerprint}`,
  );
  const envelope = await hpkeSeal(pair.publicKey, challenge, context);
  const opened = await hpkeOpen(
    pair,
    { enc: base64(envelope.enc), ciphertext: base64(envelope.ciphertext) },
    context,
  );
  if (base64(opened) !== base64(challenge))
    throw new Error(
      'The backup did not restore the registered decryption key.',
    );
  await retainConfirmedKey(roomId, pair);
  return pair;
}

export const encode = (value: string) => encoder.encode(value);
export const decodeBase64 = unbase64;
export const encodeBase64 = base64;
