import { z } from 'zod';

const PROTOCOL = 'portkey-room-file-v1';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const DB = 'portkey-room-files';
const STORE = 'secrets';
const UPLOADS = 'uploads';
const HISTORY = 'history';
const CHUNK = 1024 * 1024;
const MAX_SIZE = 250 * CHUNK;
const base64urlPattern = /^[A-Za-z0-9_-]+$/;

function encodeUrl(bytes: Uint8Array): string {
  let raw = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000)
    raw += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decodeUrl(value: string): Uint8Array {
  if (!base64urlPattern.test(value)) throw new Error('Invalid encrypted file data.');
  const raw = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
  const result = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  if (encodeUrl(result) !== value) throw new Error('Invalid encrypted file data.');
  return result;
}

function encodePacket(bytes: Uint8Array): string {
  let raw = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000)
    raw += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(raw);
}

function decodePacket(value: string): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    throw new Error('Invalid encrypted file descriptor.');
  const raw = atob(value);
  const result = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  if (encodePacket(result) !== value) throw new Error('Invalid encrypted file descriptor.');
  return result;
}

const toBuffer = (value: Uint8Array) => Uint8Array.from(value).buffer;
function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

export const roomFileBytes = (value: ArrayBuffer | ArrayBufferView) =>
  value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
export const roomFileBase64 = encodeUrl;
export const roomFileUnbase64 = decodeUrl;
export async function sha256(value: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toBuffer(value)));
}
export async function hexDigest(value: Uint8Array) {
  return [...await sha256(value)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 2);
    request.onupgradeneeded = () => {
      for (const name of [STORE, UPLOADS, HISTORY])
        if (!request.result.objectStoreNames.contains(name)) request.result.createObjectStore(name);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getStored<T>(storeName: string, key: IDBValidKey): Promise<T | undefined> {
  const database = await openDatabase();
  try {
    return await new Promise<T | undefined>((resolve, reject) => {
      const request = database.transaction(storeName).objectStore(storeName).get(key);
      request.onsuccess = () => resolve(request.result as T | undefined);
      request.onerror = () => reject(request.error);
    });
  } finally { database.close(); }
}

async function putStored(storeName: string, key: IDBValidKey, value: unknown): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(storeName, 'readwrite');
      transaction.objectStore(storeName).put(value, key);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

async function addStored(storeName: string, key: IDBValidKey, value: unknown): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(storeName, 'readwrite');
      let requestFailure: DOMException | null = null;
      let synchronousFailure: unknown;
      transaction.oncomplete = () => {
        if (synchronousFailure !== undefined) reject(synchronousFailure);
        else resolve();
      };
      transaction.onerror = () => {};
      transaction.onabort = () => {
        reject(
          synchronousFailure ??
            requestFailure ??
            transaction.error ??
            new Error('Could not preserve the pending room key rotation.'),
        );
      };

      try {
        const request = transaction.objectStore(storeName).add(value, key);
        request.onerror = () => {
          requestFailure = request.error;
        };
      } catch (error) {
        synchronousFailure = error;
        try {
          transaction.abort();
        } catch {
          reject(error);
        }
      }
    });
  } finally {
    database.close();
  }
}

export async function loadRoomFileSecret(roomId: string): Promise<Uint8Array | null> {
  const value = await getStored<string>(STORE, roomId);
  return value ? decodeUrl(value) : null;
}
export const roomFileFingerprint = (secret: Uint8Array) => hexDigest(secret);

export async function loadRoomFileHistory(roomId: string): Promise<Record<string, string>> {
  return await getStored<Record<string, string>>(HISTORY, roomId) ?? {};
}

export async function commitRoomFileKeyState(
  roomId: string,
  secret: Uint8Array,
  history: Record<string, string>,
  epoch: number,
  clearPendingFingerprint?: string,
): Promise<Record<string, string>> {
  if (secret.length !== 32) throw new Error('Invalid room file key.');
  if (!Number.isInteger(epoch) || epoch < 0 || epoch > 32)
    throw new Error('Shared file key epoch is invalid.');
  const validatedHistory = await validateRoomFileHistory(secret, history);
  const fingerprint = await roomFileFingerprint(secret);
  const stateKey = `key-state:${roomId}`;
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction([STORE, HISTORY], 'readwrite');
      let synchronousFailure: unknown;
      transaction.oncomplete = () => {
        if (synchronousFailure !== undefined) reject(synchronousFailure);
        else resolve();
      };
      transaction.onerror = () => {};
      transaction.onabort = () => {
        reject(
          synchronousFailure ??
            transaction.error ??
            new Error('Could not save the rotated room key.'),
        );
      };

      try {
        const historyStore = transaction.objectStore(HISTORY);
        const stateRequest = historyStore.get(stateKey);
        stateRequest.onsuccess = () => {
          try {
            const storedState = stateRequest.result as
              | { epoch: number; fingerprint: string }
              | undefined;
            if (
              storedState &&
              (!Number.isInteger(storedState.epoch) ||
                storedState.epoch < 0 ||
                storedState.epoch > 32 ||
                !/^[a-f0-9]{64}$/.test(storedState.fingerprint))
            )
              throw new Error('Stored shared-file key epoch metadata is invalid.');
            if (
              storedState &&
              (storedState.epoch > epoch ||
                (storedState.epoch === epoch && storedState.fingerprint !== fingerprint))
            ) {
              synchronousFailure = new Error(
                'A newer shared-file key is already stored in this browser. Reload the room before continuing.',
              );
              transaction.abort();
              return;
            }

            transaction.objectStore(STORE).put(encodeUrl(secret), roomId);
            historyStore.put(validatedHistory, roomId);
            historyStore.put({ epoch, fingerprint }, stateKey);
            if (clearPendingFingerprint) {
              const pendingRequest = historyStore.get(`rotation:${roomId}`);
              pendingRequest.onsuccess = () => {
                const pending = pendingRequest.result as
                  | { newFingerprint?: string }
                  | undefined;
                if (pending?.newFingerprint === clearPendingFingerprint)
                  historyStore.delete(`rotation:${roomId}`);
              };
            }
          } catch (error) {
            synchronousFailure = error;
            try {
              transaction.abort();
            } catch {
              reject(error);
            }
          }
        };
      } catch (error) {
        synchronousFailure = error;
        try {
          transaction.abort();
        } catch {
          reject(error);
        }
      }
    });
  } finally {
    database.close();
  }
  return validatedHistory;
}

export interface PendingRoomFileRotation { expectedFingerprint: string; newFingerprint: string; secret: string; historyEnvelope: string; epoch: number; }
export async function loadPendingRoomFileRotation(roomId: string): Promise<PendingRoomFileRotation | null> {
  return await getStored<PendingRoomFileRotation>(HISTORY, `rotation:${roomId}`) ?? null;
}
export async function savePendingRoomFileRotation(roomId: string, rotation: PendingRoomFileRotation): Promise<void> {
  try {
    await addStored(HISTORY, `rotation:${roomId}`, rotation);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'ConstraintError')
      throw new Error('Another tab already saved a rotation candidate. Reload this room to recover it before retrying.');
    throw error;
  }
}
export async function clearPendingRoomFileRotation(roomId: string): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(HISTORY, 'readwrite');
      transaction.objectStore(HISTORY).delete(`rotation:${roomId}`);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

function historyAad(roomId: string, epoch: number): Uint8Array {
  return encoder.encode(JSON.stringify({ protocol: 'portkey-room-key-history-v1', roomId, epoch, purpose: 'key-history' }));
}

async function validateRoomFileHistory(current: Uint8Array, history: Record<string, string>): Promise<Record<string, string>> {
  const entries = Object.entries(history);
  if (current.length !== 32 || entries.length > 31)
    throw new Error('Shared file key history is invalid or full.');
  const currentFingerprint = await roomFileFingerprint(current);
  const validated: Record<string, string> = {};
  for (const [fingerprint, encoded] of entries) {
    if (!/^[a-f0-9]{64}$/.test(fingerprint) || typeof encoded !== 'string' || validated[fingerprint] || fingerprint === currentFingerprint)
      throw new Error('Shared file key history failed validation.');
    const priorSecret = decodeUrl(encoded);
    if (priorSecret.length !== 32 || await roomFileFingerprint(priorSecret) !== fingerprint)
      throw new Error('Shared file key history failed validation.');
    validated[fingerprint] = encoded;
  }
  return validated;
}

export function sameRoomFileHistory(left: Record<string, string>, right: Record<string, string>): boolean {
  const canonical = (value: Record<string, string>) => JSON.stringify(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)));
  return canonical(left) === canonical(right);
}

export async function encryptRoomFileHistory(roomId: string, epoch: number, current: Uint8Array, history: Record<string, string>): Promise<string> {
  const validated = await validateRoomFileHistory(current, history);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', toBuffer(current), 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: toBuffer(historyAad(roomId, epoch)) }, key, encoder.encode(JSON.stringify(validated))));
  return encodePacket(concat(iv, ciphertext));
}

export async function decryptRoomFileHistory(roomId: string, epoch: number, current: Uint8Array, envelope: string | null): Promise<Record<string, string>> {
  if (!envelope) return {};
  const packet = decodePacket(envelope);
  if (packet.length < 28 || packet.length > 8192) throw new Error('Shared file key history is invalid.');
  const key = await crypto.subtle.importKey('raw', toBuffer(current), 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toBuffer(packet.slice(0, 12)), additionalData: toBuffer(historyAad(roomId, epoch)) }, key, toBuffer(packet.slice(12)));
  const json = decoder.decode(plaintext);
  const parsed: unknown = JSON.parse(json);
  if (JSON.stringify(parsed) !== json)
    throw new Error('Shared file key history is not canonical JSON.');
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Shared file key history is invalid.');
  const entries = Object.entries(parsed as Record<string, unknown>);
  const currentFingerprint = await roomFileFingerprint(current);
  if (entries.length > 31) throw new Error('Shared file key history is invalid.');
  const result: Record<string, string> = {};
  for (const [fingerprint, encoded] of entries) {
    if (!/^[a-f0-9]{64}$/.test(fingerprint) || typeof encoded !== 'string' || fingerprint === currentFingerprint || result[fingerprint]) throw new Error('Shared file key history is invalid.');
    const secret = decodeUrl(encoded);
    if (secret.length !== 32 || await roomFileFingerprint(secret) !== fingerprint) throw new Error('Shared file key history is invalid.');
    result[fingerprint] = encoded;
  }
  return result;
}

export function readFilesFragment(): { secret: Uint8Array | null; invalid: boolean } {
  const values = new URLSearchParams(location.hash.slice(1)).getAll('files');
  if (!values.length) return { secret: null, invalid: false };
  try {
    if (values.length !== 1 || values[0].length !== 43) throw new Error();
    const secret = decodeUrl(values[0]);
    if (secret.length !== 32) throw new Error();
    return { secret, invalid: false };
  } catch { return { secret: null, invalid: true }; }
}
export function filesFragment(secret: Uint8Array | null) {
  return secret ? `#files=${encodeURIComponent(encodeUrl(secret))}` : '';
}
export function removeFilesFragment(): void {
  const fragment = new URLSearchParams(location.hash.slice(1));
  fragment.delete('files');
  history.replaceState(null, '', `${location.pathname}${location.search}${fragment.size ? `#${fragment}` : ''}`);
}

export interface ReadyPlan {
  roomId: string;
  id: string;
  filename: string;
  size: number;
  mediaType: string;
  descriptor: string;
  chunkCount: number;
  encryptedBytes: number;
  chunkHashes: string[];
  state: 'ready' | 'preparing';
  keyFingerprint?: string;
}
export interface RoomFileReceipt {
  id: string;
  acceptedAt: string;
  encryptedBytes: number;
  manifestSha256: string;
}

const planSchema = z.object({
  roomId: z.string().uuid(), id: z.string().uuid(), filename: z.string().min(1).max(255),
  size: z.number().int().min(0).max(MAX_SIZE), mediaType: z.string().min(1).max(127),
  descriptor: z.string().min(1).max(8192), chunkCount: z.number().int().min(1).max(250),
  encryptedBytes: z.number().int().min(16).max(MAX_SIZE + 16 * 250),
  chunkHashes: z.array(z.string().regex(/^[a-f0-9]{64}$/)).max(250),
  state: z.enum(['ready', 'preparing']),
  keyFingerprint: z.string().regex(/^[a-f0-9]{64}$/).optional(),
}).strict();

async function savePlan(plan: ReadyPlan): Promise<void> { await putStored(UPLOADS, `plan:${plan.id}`, plan); }
async function saveChunk(id: string, index: number, data: Uint8Array): Promise<void> {
  await putStored(UPLOADS, `chunk:${id}:${index}`, toBuffer(data));
}
async function getChunk(id: string, index: number): Promise<Uint8Array | null> {
  const value = await getStored<ArrayBuffer>(UPLOADS, `chunk:${id}:${index}`);
  return value ? new Uint8Array(value) : null;
}

export async function listRoomFilePlans(roomId: string): Promise<ReadyPlan[]> {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const plans: ReadyPlan[] = [];
      const transaction = database.transaction(UPLOADS);
      const cursor = transaction.objectStore(UPLOADS).openCursor();
      cursor.onsuccess = () => {
        const entry = cursor.result;
        if (!entry) return;
        if (String(entry.key).startsWith('plan:')) {
          const parsed = planSchema.safeParse(entry.value);
          if (parsed.success && parsed.data.roomId === roomId) plans.push(parsed.data);
        }
        entry.continue();
      };
      transaction.oncomplete = () => resolve(plans);
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

export async function clearRoomFilePlan(id: string): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(UPLOADS, 'readwrite');
      const store = transaction.objectStore(UPLOADS);
      const cursor = store.openCursor();
      cursor.onsuccess = () => {
        const entry = cursor.result;
        if (!entry) return;
        if (String(entry.key) === `plan:${id}` || String(entry.key).startsWith(`chunk:${id}:`)) entry.delete();
        entry.continue();
      };
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally { database.close(); }
}

function chunkNonce(prefix: Uint8Array, index: number): Uint8Array {
  const nonce = new Uint8Array(12);
  nonce.set(prefix);
  new DataView(nonce.buffer).setUint32(8, index, false);
  return nonce;
}
function chunkAad(roomId: string, id: string, index: number, plainLength: number): Uint8Array {
  return encoder.encode(JSON.stringify({ protocol: PROTOCOL, roomId, id, purpose: 'chunk', index, plainLength }));
}

export async function prepareRoomFile(file: File, roomId: string, master: Uint8Array, onProgress?: (done: number, total: number) => void): Promise<ReadyPlan> {
  if (file.size > MAX_SIZE) throw new Error('Files can be up to 250 MiB.');
  if (!file.name || file.name.length > 255) throw new Error('File names must be between 1 and 255 characters.');
  const mediaType = file.type || 'application/octet-stream';
  if (mediaType.length > 127) throw new Error('The file media type is too long.');
  const id = crypto.randomUUID();
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const noncePrefix = crypto.getRandomValues(new Uint8Array(8));
  const chunkCount = Math.max(1, Math.ceil(file.size / CHUNK));
  const metadata = { protocol: PROTOCOL, roomId, id, filename: file.name, mediaType, size: file.size, fileKey: encodeUrl(fileKey), noncePrefix: encodeUrl(noncePrefix) };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const metadataKey = await crypto.subtle.importKey('raw', toBuffer(master), 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
    name: 'AES-GCM', iv,
    additionalData: encoder.encode(JSON.stringify({ protocol: PROTOCOL, roomId, id, purpose: 'descriptor' })),
  }, metadataKey, encoder.encode(JSON.stringify(metadata))));
  const descriptor = concat(iv, ciphertext);
  const plan: ReadyPlan = {
    roomId, id, filename: file.name, size: file.size, mediaType,
    descriptor: encodePacket(descriptor), chunkCount,
    encryptedBytes: file.size + 16 * chunkCount, chunkHashes: [], state: 'preparing', keyFingerprint: await roomFileFingerprint(master),
  };
  // An interrupted plan is visible as discard-only; its reserved nonces are never reused.
  await savePlan(plan);
  try {
    const contentKey = await crypto.subtle.importKey('raw', toBuffer(fileKey), 'AES-GCM', false, ['encrypt']);
    for (let index = 0; index < chunkCount; index++) {
      const start = index * CHUNK;
      const length = Math.min(CHUNK, file.size - start);
      const plaintext = new Uint8Array(await file.slice(start, start + length).arrayBuffer());
      if (plaintext.length !== length) throw new Error('The selected file could not be read completely.');
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({
        name: 'AES-GCM', iv: toBuffer(chunkNonce(noncePrefix, index)),
        additionalData: toBuffer(chunkAad(roomId, id, index, length)),
      }, contentKey, toBuffer(plaintext)));
      await saveChunk(id, index, encrypted);
      plan.chunkHashes.push(await hexDigest(encrypted));
      onProgress?.(index + 1, chunkCount);
    }
    plan.state = 'ready';
    await savePlan(plan);
    return plan;
  } catch (error) {
    await clearRoomFilePlan(id);
    throw error;
  }
}

export async function roomFileManifest(plan: ReadyPlan): Promise<string> {
  return hexDigest(concat(decodePacket(plan.descriptor), ...plan.chunkHashes.map((hash) => Uint8Array.from(hash.match(/../g)!, (byte) => Number.parseInt(byte, 16)))));
}
export const loadRoomFileCipherChunk = getChunk;

function isRetryable(error: unknown): boolean {
  return error instanceof TypeError ||
    (error instanceof Error && 'status' in error &&
      (Number((error as { status: number }).status) === 429 ||
        (Number((error as { status: number }).status) >= 500 && Number((error as { status: number }).status) < 600)));
}

function retryDelay(error: unknown, retryIndex: number): number {
  if (error instanceof Error && 'retryAfterSeconds' in error) {
    const seconds = Number((error as { retryAfterSeconds: number }).retryAfterSeconds);
    if (Number.isFinite(seconds) && seconds > 0) return Math.min(60_000, seconds * 1_000);
  }
  return Math.min(60_000, 500 * 2 ** retryIndex);
}

async function waitForRetry(delayMs: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, delayMs);
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason ?? new DOMException('Transfer aborted.', 'AbortError'));
    };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
}

async function withTransferRetry<T>(work: () => Promise<T>, signal: AbortSignal): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= 5; attempt++) {
    signal.throwIfAborted();
    try {
      return await work();
    } catch (error) {
      lastError = error;
      if (signal.aborted || !isRetryable(error) || attempt === 5) throw error;
      await waitForRetry(retryDelay(error, attempt), signal);
    }
  }
  throw lastError;
}

const receiptSchema = z.object({
  id: z.string().uuid(),
  acceptedAt: z.string().min(1),
  encryptedBytes: z.number().int().positive(),
  manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

function validateReceipt(value: unknown, plan: ReadyPlan, manifestSha256: string): RoomFileReceipt {
  const receipt = receiptSchema.parse(value);
  if (receipt.id !== plan.id || receipt.encryptedBytes !== plan.encryptedBytes || receipt.manifestSha256 !== manifestSha256 || !Number.isFinite(Date.parse(receipt.acceptedAt)))
    throw new Error('The server returned a receipt that does not match this shared file.');
  return receipt;
}

export async function uploadRoomFile(plan: ReadyPlan, fingerprint: string, signal: AbortSignal, onProgress: (done: number, total: number) => void): Promise<RoomFileReceipt> {
  if (plan.state !== 'ready') throw new Error('This interrupted preparation cannot resume. Discard it and select the file again.');
  if (!plan.keyFingerprint) throw new Error('This saved upload predates key binding. Select the original file again to encrypt it with the current shared file key.');
  if (plan.keyFingerprint !== fingerprint) throw new Error('This saved upload uses an older shared file key. Select the original file again to encrypt a new copy before sharing.');
  const { api, apiBytes } = await import('./api.js');
  const state = await withTransferRetry(() => api<{ uploadedChunks: number[]; complete: boolean; receipt?: unknown }>(`/rooms/${plan.roomId}/files`, 'POST', {
    id: plan.id, keyFingerprint: fingerprint, descriptor: plan.descriptor,
    chunkCount: plan.chunkCount, encryptedBytes: plan.encryptedBytes,
  }, signal), signal);
  const manifestSha256 = await roomFileManifest(plan);
  if (state.complete) return validateReceipt(state.receipt, plan, manifestSha256);
  for (let index = 0; index < plan.chunkCount; index++) {
    if (state.uploadedChunks.includes(index)) continue;
    const chunk = await getChunk(plan.id, index);
    if (!chunk) throw new Error('An encrypted upload chunk is missing from this browser.');
    await withTransferRetry(
      () => apiBytes(`/rooms/${plan.roomId}/files/${plan.id}/chunks/${index}`, 'PUT', chunk, signal),
      signal,
    );
    onProgress(index + 1, plan.chunkCount);
  }
  const result = await withTransferRetry(
    () => api<{ receipt?: unknown }>(`/rooms/${plan.roomId}/files/${plan.id}/complete`, 'POST', { manifestSha256 }, signal),
    signal,
  );
  return validateReceipt(result.receipt, plan, manifestSha256);
}

export function retryRoomFileRequest<T>(work: () => Promise<T>, signal: AbortSignal): Promise<T> {
  return withTransferRetry(work, signal);
}

const metadataSchema = z.object({
  protocol: z.literal(PROTOCOL), roomId: z.string().uuid(), id: z.string().uuid(),
  filename: z.string().min(1).max(255), mediaType: z.string().min(1).max(127),
  size: z.number().int().min(0).max(MAX_SIZE),
  fileKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/), noncePrefix: z.string().regex(/^[A-Za-z0-9_-]{11}$/),
}).strict();

function safeFilename(value: string): string {
  return value.replace(/[\\/\u0000-\u001f]/g, '_').replace(/[^\p{L}\p{N} ._()-]/gu, '_').slice(0, 255) || 'shared-file';
}
type CipherChunkReader = (index: number) => Promise<{ bytes: Uint8Array; sha256: string }>;
type DownloadDirectory = FileSystemDirectoryHandle & { entries(): AsyncIterableIterator<[string, FileSystemHandle]> };
const localDownloadUrls = new Map<string, string>();

async function downloadDirectory(): Promise<DownloadDirectory | null> {
  const storage = navigator.storage as StorageManager & { getDirectory?: () => Promise<FileSystemDirectoryHandle> };
  if (!storage.getDirectory) return null;
  return await (await storage.getDirectory()).getDirectoryHandle('portkey-verified-downloads', { create: true }) as DownloadDirectory;
}

export async function decryptRoomFileToDownload(
  roomId: string,
  item: { id: string; descriptor: string; chunkCount: number; manifestSha256: string },
  master: Uint8Array,
  readCipherChunk: CipherChunkReader,
  onProgress: (read: number, total: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  signal?.throwIfAborted();
  const metadata = await decryptRoomFileDescriptor(roomId, item.id, item.descriptor, master, signal);
  signal?.throwIfAborted();
  if (item.chunkCount !== Math.max(1, Math.ceil(metadata.size / CHUNK)))
    throw new Error('The encrypted file manifest has the wrong number of chunks.');

  const picker = (window as Window & { showSaveFilePicker?: (options: { suggestedName: string }) => Promise<FileSystemFileHandle> }).showSaveFilePicker;
  const opfs = await downloadDirectory();
  if (!opfs && metadata.size > 50 * 1024 * 1024)
    throw new Error('This browser supports downloads up to 50 MiB. Use a browser with private temporary storage for larger files.');
  if (opfs) {
    let copies = 0;
    for await (const [name] of opfs.entries()) if (/^portkey-[a-f0-9-]{36}\.tmp$/.test(name)) copies++;
    if (copies >= 5) throw new Error('Remove local download copies before starting another download.');
  }
  const target = picker && opfs ? await picker({ suggestedName: safeFilename(metadata.filename) }) : null;
  const tempName = `portkey-${crypto.randomUUID()}.tmp`;
  const tempHandle = opfs ? await opfs.getFileHandle(tempName, { create: true }) : null;
  const writer = tempHandle ? await tempHandle.createWritable() : null;
  const fallback: Uint8Array[] = [];
  const contentKey = await crypto.subtle.importKey('raw', toBuffer(decodeUrl(metadata.fileKey)), 'AES-GCM', false, ['decrypt']);
  const noncePrefix = decodeUrl(metadata.noncePrefix);
  const chunkHashes: Uint8Array[] = [];
  let total = 0;
  let keepCopy = false;
  try {
    for (let index = 0; index < item.chunkCount; index++) {
      signal?.throwIfAborted();
      const chunk = await readCipherChunk(index);
      signal?.throwIfAborted();
      const actualHash = await hexDigest(chunk.bytes);
      if (actualHash !== chunk.sha256) throw new Error('A downloaded encrypted chunk failed its integrity check.');
      chunkHashes.push(Uint8Array.from(actualHash.match(/../g)!, (byte) => Number.parseInt(byte, 16)));
      const plainLength = Math.min(CHUNK, metadata.size - index * CHUNK);
      let decrypted: Uint8Array;
      try {
        decrypted = new Uint8Array(await crypto.subtle.decrypt({
          name: 'AES-GCM', iv: toBuffer(chunkNonce(noncePrefix, index)),
          additionalData: toBuffer(chunkAad(roomId, item.id, index, plainLength)),
        }, contentKey, toBuffer(chunk.bytes)));
      } catch (cause) {
        if (signal?.aborted) throw signal.reason ?? cause;
        throw new Error('This shared file failed authentication. No download was saved.');
      }
      signal?.throwIfAborted();
      if (decrypted.length !== plainLength) throw new Error('A shared file chunk failed verification.');
      total += decrypted.length;
      if (writer) await writer.write(toBuffer(decrypted)); else fallback.push(decrypted);
      onProgress(total, metadata.size);
    }
    const manifest = await hexDigest(concat(decodePacket(item.descriptor), ...chunkHashes));
    if (total !== metadata.size || manifest !== item.manifestSha256)
      throw new Error('This shared file failed its authenticated manifest check.');
    signal?.throwIfAborted();
    if (writer) {
      await writer.close();
      signal?.throwIfAborted();
      const staged = await tempHandle!.getFile();
      signal?.throwIfAborted();
      if (staged.size !== metadata.size) throw new Error('The staged file has the wrong size.');
      if (target) {
        const output = await target.createWritable();
        await staged.stream().pipeTo(output);
      } else {
        const url = URL.createObjectURL(new Blob([staged], { type: metadata.mediaType }));
        localDownloadUrls.set(tempName, url);
        const anchor = document.createElement('a'); anchor.href = url; anchor.download = safeFilename(metadata.filename); anchor.click();
        keepCopy = true;
      }
    } else {
      signal?.throwIfAborted();
      const blob = new Blob(fallback.map(toBuffer), { type: metadata.mediaType });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = safeFilename(metadata.filename); anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }
  } catch (error) {
    if (writer) await writer.abort().catch(() => undefined);
    throw error;
  } finally {
    if (opfs && tempHandle && !keepCopy) await opfs.removeEntry(tempName).catch(() => undefined);
  }
}

export async function decryptRoomFileDescriptor(
  roomId: string,
  id: string,
  descriptor: string,
  master: Uint8Array,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  const packet = decodePacket(descriptor);
  if (packet.length < 28 || packet.length > 8192) throw new Error('The encrypted file descriptor has an invalid size.');
  const iv = packet.slice(0, 12);
  const descriptorCipher = packet.slice(12);
  const key = await crypto.subtle.importKey('raw', toBuffer(master), 'AES-GCM', false, ['decrypt']);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: toBuffer(iv),
      additionalData: encoder.encode(JSON.stringify({ protocol: PROTOCOL, roomId, id, purpose: 'descriptor' })),
    }, key, toBuffer(descriptorCipher));
  } catch (cause) {
    if (signal?.aborted) throw signal.reason ?? cause;
    throw new Error('This shared file failed authentication. No download was saved.', { cause });
  }
  signal?.throwIfAborted();
  const parsed = metadataSchema.safeParse(JSON.parse(decoder.decode(plaintext)));
  if (!parsed.success || parsed.data.roomId !== roomId || parsed.data.id !== id)
    throw new Error('This shared file has invalid or mismatched metadata.');
  return parsed.data;
}

export async function clearRoomFileDownloadCopies(): Promise<number> {
  const directory = await downloadDirectory();
  if (!directory) return 0;
  let removed = 0;
  for await (const [name] of directory.entries()) {
    if (!/^portkey-[a-f0-9-]{36}\.tmp$/.test(name)) continue;
    await directory.removeEntry(name);
    const url = localDownloadUrls.get(name);
    if (url) URL.revokeObjectURL(url);
    localDownloadUrls.delete(name);
    removed++;
  }
  return removed;
}
