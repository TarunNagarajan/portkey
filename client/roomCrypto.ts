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
// A historical protocol label that is bound into every encrypted descriptor,
// envelope info and chunk AAD. It must not change, or ciphertext published by
// earlier builds could no longer be decrypted.
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
    };
    opening.onsuccess = () => resolve(opening.result);
    opening.onerror = () => reject(opening.error);
  });
}

export async function storeKey(roomId: string, value: RecipientKeyPair) {
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
  // Import both coordinates with the private scalar. Some engines cannot
  // reconstruct an EC public key from a scalar-only PKCS#8 import.
  const b64url = (value: Uint8Array) => base64(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const privateKey = await suite.kem.importKey('jwk', {
    kty: 'EC', crv: 'P-256', x: b64url(pair.publicKey.slice(1, 33)),
    y: b64url(pair.publicKey.slice(33)), d: b64url(pair.privateKey),
  }, false);
  const publicKey = await suite.kem.deserializePublicKey(pair.publicKey);
  const recipient = await suite.createRecipientContext({
    recipientKey: { privateKey, publicKey },
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

export interface DistributionRecipient {
  id: string;
  publicKey: Uint8Array;
}

export interface DistributionPlan {
  roomId: string;
  fileId: string;
  file: File;
  fileSize: number;
  sourceMissing?: boolean;
  chunkSizes: number[];
  fileKey: Uint8Array;
  keySalt: string;
  noncePrefix: string;
  descriptor: string;
  envelopes: { recipientId: string; enc: string; ciphertext: string }[];
  recipientFingerprints: Record<string, string>;
  roomEnvelope?: Envelope & { fingerprint: string };
}

// Encrypts a file once for many recipients. The file key is sealed with HPKE
// to each approved participant's registered public key, so the server only
// ever stores ciphertext and per-recipient envelopes.
export async function prepareDistribution(
  file: File,
  roomId: string,
  fileId: string,
  recipients: DistributionRecipient[],
  roomPublicKey?: Uint8Array,
): Promise<DistributionPlan> {
  const count = Math.max(1, Math.ceil(file.size / (1024 * 1024)));
  if (count > 250)
    throw new Error('The file exceeds the 250 MiB distribution limit.');
  if (recipients.length < 1)
    throw new Error('There are no approved participants to receive this file.');
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const keySalt = crypto.getRandomValues(new Uint8Array(32));
  const noncePrefix = crypto.getRandomValues(new Uint8Array(8));
  const metadataNonce = crypto.getRandomValues(new Uint8Array(12));
  const metadataKey = await deriveAes(fileKey, keySalt, 'metadata');
  const sizes = Array.from({ length: count }, (_, index) =>
    Math.max(0, Math.min(1024 * 1024, file.size - index * 1024 * 1024)),
  );
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
      objectId: fileId,
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
  const envelopes = await Promise.all(
    recipients.map(async (recipient) => {
      const recipientFingerprint = await digest(recipient.publicKey);
      const seal = await hpkeSeal(
        recipient.publicKey,
        fileKey,
        keyContext(roomId, fileId, recipientFingerprint, 'submission-file-key'),
      );
      return {
        recipientId: recipient.id,
        enc: base64(seal.enc),
        ciphertext: base64(seal.ciphertext),
      };
    }),
  );
  return {
    roomId,
    fileId,
    file,
    fileSize: file.size,
    chunkSizes: sizes,
    fileKey,
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
    envelopes,
    roomEnvelope: roomPublicKey ? await sealRoomFileKey(roomId, fileId, fileKey, roomPublicKey) : undefined,
    recipientFingerprints: Object.fromEntries(await Promise.all(recipients.map(async recipient => [recipient.id, await digest(recipient.publicKey)]))),
  };
}

export async function encryptDistributionChunk(
  plan: DistributionPlan,
  index: number,
) {
  const plainLength = plan.chunkSizes[index];
  const plaintext = new Uint8Array(
    await plan.file
      .slice(index * 1024 * 1024, index * 1024 * 1024 + plainLength)
      .arrayBuffer(),
  );
  if (plaintext.length !== plainLength)
    throw new Error('The source file could not be read completely.');
  const contentKey = await deriveAes(plan.fileKey, unbase64(plan.keySalt), 'content');
  const ciphertext = bytes(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: bufferSource(chunkNonce(unbase64(plan.noncePrefix), index)),
        additionalData: bufferSource(
          chunkContext(plan.roomId, plan.fileId, index, plaintext.length),
        ),
        tagLength: 128,
      },
      contentKey,
      bufferSource(plaintext),
    ),
  );
  return { ciphertext, sha256: await digest(ciphertext) };
}

export async function distributionManifest(
  plan: DistributionPlan,
  chunkDigests: string[],
) {
  return digest(
    concat(
      unbase64(plan.descriptor),
      ...chunkDigests.map((value) =>
        Uint8Array.from(value.match(/../g) ?? [], (char) =>
          Number.parseInt(char, 16),
        ),
      ),
    ),
  );
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
      .slice(0, 255) || 'room-file'
  );
}

type CipherChunkReader = (
  index: number,
) => Promise<{ bytes: Uint8Array; sha256: string }>;

type DownloadDirectory = FileSystemDirectoryHandle & {
  entries(): AsyncIterableIterator<[string, FileSystemHandle]>;
};
const localDownloadUrls = new Map<string, string>();

export async function privateDirectory(): Promise<FileSystemDirectoryHandle | null> {
  if (!navigator.storage?.getDirectory) return null;
  try { return await navigator.storage.getDirectory(); }
  catch (error) {
    if (error instanceof DOMException && ['NotAllowedError', 'NotSupportedError', 'UnknownError', 'SecurityError'].includes(error.name)) return null;
    throw error;
  }
}
async function downloadDirectory() {
  const root = await privateDirectory();
  if (!root) return null;
  return await root.getDirectoryHandle('portkey-verified-downloads', { create: true }) as DownloadDirectory;
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

export async function decryptRoomFileToDownload(
  roomId: string,
  file: {
    id: string;
    descriptor: string;
    envelope: Envelope;
    chunkCount: number;
    manifestSha256: string;
    envelopeKind?: 'room' | 'personal';
  },
  pair: RecipientKeyPair,
  readCipherChunk: CipherChunkReader,
  onProgress: (read: number, total: number) => void,
) {
  const info = keyContext(
    roomId,
    file.id,
    pair.fingerprint,
    file.envelopeKind === 'room' ? 'room-file-key' : 'submission-file-key',
  );
  const fileKey = await hpkeOpen(pair, file.envelope, info);
  if (fileKey.length !== 32)
    throw new Error('The encrypted file key has an invalid length.');
  const descriptor = await decryptDescriptor(
    file.descriptor,
    fileKey,
    roomId,
    file.id,
  );
  if (descriptor.chunkSizes.length !== file.chunkCount)
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
    for (let index = 0; index < file.chunkCount; index += 1) {
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
        file.id,
        index,
        descriptor.chunkSizes[index],
      );
      total += plaintext.length;
      if (tempWriter) await tempWriter.write(bufferSource(plaintext));
      else fallbackParts.push(plaintext);
      onProgress(total, descriptor.size);
    }
    const manifest = await digest(
      concat(
        Uint8Array.from(atob(file.descriptor), (character) =>
          character.charCodeAt(0),
        ),
        ...hashes,
      ),
    );
    if (total !== descriptor.size || manifest !== file.manifestSha256)
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
  roomAccess?: RecipientKeyPair,
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
      ...(roomAccess ? { roomAccess: encodeRoomAccess(roomAccess) } : {}),
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
  options: { storageId?: string; roomAccessFingerprint?: string | null } = {},
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
      roomAccess: z.string().max(1000).optional(),
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
    throw new Error('The backup key does not match this room’s registered key.');
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
  const shared = value.roomAccess ? await decodeRoomAccess(value.roomAccess) : null;
  if (shared && options.roomAccessFingerprint && shared.fingerprint !== options.roomAccessFingerprint) throw new Error('The room access backup does not match the registered room.');
  await retainConfirmedKey(options.storageId ?? roomId, pair);
  if (shared) await retainConfirmedKey(roomAccessStorageId(roomId), shared);
  return pair;
}

export const decodeBase64 = unbase64;
export const encodeBase64 = base64;

export async function replaceStoredKey(roomId: string, pair: RecipientKeyPair) {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(KEY_STORE, 'readwrite');
      tx.objectStore(KEY_STORE).put({ publicKey: base64(pair.publicKey), privateKey: base64(pair.privateKey), fingerprint: pair.fingerprint }, roomId);
      tx.oncomplete = () => resolve(); tx.onabort = tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}
export async function loadRegisteredKey(roomId: string, fingerprint: string) {
  const current = await loadKey(roomId);
  if (current?.fingerprint === fingerprint) return current;
  const candidate = await loadKey(`${roomId}:key:${fingerprint}`);
  if (candidate) { await replaceStoredKey(roomId, candidate); return candidate; }
  return current;
}
export async function rewrapFileKey(roomId: string, item: { id: string; envelope: Envelope; envelopeKind?: 'room' | 'personal' }, pair: RecipientKeyPair, publicKey: Uint8Array) {
  const key = await hpkeOpen(pair, item.envelope, keyContext(roomId, item.id, pair.fingerprint, item.envelopeKind === 'room' ? 'room-file-key' : 'submission-file-key'));
  if (key.length !== 32) throw new Error('The file key has invalid bounds.');
  const sealed = await hpkeSeal(publicKey, key, keyContext(roomId, item.id, await digest(publicKey), 'submission-file-key'));
  return { enc: base64(sealed.enc), ciphertext: base64(sealed.ciphertext) };
}
export async function roomFileName(roomId: string, item: { id: string; envelope: Envelope; descriptor: string; envelopeKind?: 'room' | 'personal' }, pair: RecipientKeyPair) {
  const key = await hpkeOpen(pair, item.envelope, keyContext(roomId, item.id, pair.fingerprint, item.envelopeKind === 'room' ? 'room-file-key' : 'submission-file-key'));
  return (await decryptDescriptor(item.descriptor, key, roomId, item.id)).filename;
}


export const roomAccessStorageId = (roomId: string) => `${roomId}:room-access`;
export function encodeRoomAccess(pair: RecipientKeyPair) {
  return base64(encoder.encode(JSON.stringify([base64(pair.publicKey), base64(pair.privateKey)]))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export async function decodeRoomAccess(token: string): Promise<RecipientKeyPair> {
  if (!/^[A-Za-z0-9_-]{1,1000}$/.test(token)) throw new Error('The room invitation is invalid. Ask the organizer for a fresh invitation.');
  const raw = token.replaceAll('-', '+').replaceAll('_', '/');
  const values = z.tuple([z.string().max(100), z.string().max(100)]).parse(JSON.parse(decoder.decode(unbase64(raw))));
  const publicKey = unbase64(values[0]), privateKey = unbase64(values[1]);
  if (publicKey.length !== 65 || publicKey[0] !== 4 || privateKey.length !== 32) throw new Error('The room invitation key is invalid.');
  const pair = { publicKey, privateKey, fingerprint: await digest(publicKey) };
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const context = encoder.encode('portkey-room-access-invitation-v1');
  const envelope = await hpkeSeal(publicKey, challenge, context);
  const opened = await hpkeOpen(pair, { enc: base64(envelope.enc), ciphertext: base64(envelope.ciphertext) }, context);
  if (base64(opened) !== base64(challenge)) throw new Error('The room invitation keypair is invalid.');
  return pair;
}
export async function deriveRoomAccessKey(owner: RecipientKeyPair, roomId: string): Promise<RecipientKeyPair> {
  const { p256 } = await import('@noble/curves/nist.js');
  const material = await crypto.subtle.importKey('raw', bufferSource(owner.privateKey), 'HKDF', false, ['deriveBits']);
  // Derive the scalar and public point without scalar-only WebCrypto imports:
  // Firefox cannot reliably export those imported keys. Noble supplies P-256
  // point multiplication; HPKE/WebCrypto still handle file-key encryption.
  for (let counter = 0; counter < 256; counter++) {
    const info = counter === 0 ? 'portkey-room-access-v1' : `portkey-room-access-v1:${counter}`;
    const privateKey = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(roomId), info: encoder.encode(info) }, material, 256));
    if (!p256.utils.isValidSecretKey(privateKey)) continue;
    const publicKey = p256.getPublicKey(privateKey, false);
    return { publicKey, privateKey, fingerprint: await digest(publicKey) };
  }
  throw new Error('Unable to derive a room receiving key.');
}
export async function sealRoomFileKey(roomId: string, fileId: string, fileKey: Uint8Array, publicKey: Uint8Array) {
  const fingerprint = await digest(publicKey);
  const envelope = await hpkeSeal(publicKey, fileKey, keyContext(roomId, fileId, fingerprint, 'room-file-key'));
  return { fingerprint, enc: base64(envelope.enc), ciphertext: base64(envelope.ciphertext) };
}
export async function shareExistingFile(roomId: string, item: { id: string; envelope: Envelope; envelopeKind?: 'room' | 'personal' }, owner: RecipientKeyPair, roomPublicKey: Uint8Array) {
  const key = await hpkeOpen(owner, item.envelope, keyContext(roomId, item.id, owner.fingerprint, 'submission-file-key'));
  if (key.length !== 32) throw new Error('The stored file key is invalid.');
  return sealRoomFileKey(roomId, item.id, key, roomPublicKey);
}
