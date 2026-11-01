import { useCallback, useEffect, useRef, useState } from 'react';
import type { Room } from '../shared/rooms.js';
import { ApiError, api, apiBytes } from './api.js';
import {
  clearRoomFilePlan,
  decryptRoomFileDescriptor,
  decryptRoomFileToDownload,
  clearRoomFileDownloadCopies,
  listRoomFilePlans,
  loadRoomFileSecret,
  prepareRoomFile,
  readFilesFragment,
  removeFilesFragment,
  roomFileFingerprint,
  retryRoomFileRequest,
  saveRoomFileSecret,
  uploadRoomFile,
  type ReadyPlan,
} from './roomFileCrypto.js';

interface ListedFile {
  id: string;
  descriptor: string;
  chunkCount: number;
  encryptedBytes: number;
  manifestSha256: string;
  createdAt: string;
  receipt: { acceptedAt: string };
  canDelete: boolean;
}
interface FileListPage {
  files: ListedFile[];
  nextCursor: string | null;
  activeIds: string[];
}
interface TransferProgress {
  done: number;
  total: number;
}

function isAccessLost(error: unknown): boolean {
  return error instanceof ApiError && [401, 403, 410].includes(error.status);
}

function mergeFiles(current: ListedFile[], incoming: ListedFile[]): ListedFile[] {
  const merged = new Map(current.map((file) => [file.id, file]));
  for (const file of incoming) merged.set(file.id, file);
  return [...merged.values()].sort((left, right) =>
    Date.parse(right.createdAt) - Date.parse(left.createdAt) || right.id.localeCompare(left.id),
  );
}

export function RoomFiles({
  room,
  onKeyReady,
}: {
  room: Room;
  onKeyReady?: (key: Uint8Array | null) => void;
}) {
  const [secret, setSecret] = useState<Uint8Array | null>(null);
  const [registered, setRegistered] = useState<string | null>(null);
  const [files, setFiles] = useState<ListedFile[]>([]);
  const [plans, setPlans] = useState<ReadyPlan[]>([]);
  const [fileNames, setFileNames] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [connectionError, setConnectionError] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [available, setAvailable] = useState(false);
  const [initialized, setInitialized] = useState(false);
  const [accessUnavailable, setAccessUnavailable] = useState(false);
  const [localCopyCount, setLocalCopyCount] = useState(0);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [progress, setProgress] = useState<TransferProgress | null>(null);
  const [localDiscardPlan, setLocalDiscardPlan] = useState<string | null>(null);
  const activeController = useRef<AbortController | null>(null);
  const refreshLock = useRef(false);
  const loadedOlderPages = useRef(false);
  const lifecycle = useRef(0);
  const fragmentGeneration = useRef(0);
  const requestControllers = useRef(new Set<AbortController>());

  const createRequest = useCallback(() => {
    const controller = new AbortController();
    requestControllers.current.add(controller);
    return controller;
  }, []);
  const finishRequest = useCallback((controller: AbortController) => {
    requestControllers.current.delete(controller);
  }, []);
  const rejectActiveKey = useCallback((message: string, malformed: boolean) => {
    setSecret(null);
    onKeyReady?.(null);
    setFiles([]);
    setFileNames({});
    setNextCursor(null);
    activeController.current?.abort();
    for (const controller of requestControllers.current) controller.abort();
    requestControllers.current.clear();
    setInvalid(malformed);
    setError(message);
  }, [onKeyReady]);
  const markAccessLost = useCallback(() => {
    setFiles([]);
    setFileNames({});
    setNextCursor(null);
    setAccessUnavailable(true);
    loadedOlderPages.current = false;
    activeController.current?.abort();
    for (const controller of requestControllers.current) controller.abort();
    requestControllers.current.clear();
  }, []);

  useEffect(() => {
    lifecycle.current += 1;
    return () => {
      lifecycle.current += 1;
      for (const controller of requestControllers.current) controller.abort();
      requestControllers.current.clear();
      activeController.current?.abort();
    };
  }, [room.id, room.status]);

  const refresh = useCallback(async () => {
    if (room.status !== 'open') {
      setFiles([]);
      setFileNames({});
      setNextCursor(null);
      loadedOlderPages.current = false;
      return;
    }
    if (refreshLock.current) return;
    refreshLock.current = true;
    const generation = lifecycle.current;
    const controller = createRequest();
    try {
      const page = await api<FileListPage>(`/rooms/${room.id}/files`, 'GET', undefined, controller.signal);
      if (generation !== lifecycle.current || controller.signal.aborted) return;
      const activeIds = new Set(page.activeIds);
      setFiles((current) => mergeFiles(
        current.filter((file) => activeIds.has(file.id)),
        page.files,
      ));
      setFileNames((current) => Object.fromEntries(Object.entries(current).filter(([id]) => activeIds.has(id))));
      setAccessUnavailable(false);
      if (!loadedOlderPages.current) setNextCursor(page.nextCursor);
      setConnectionError('');
    } catch (cause) {
      if (controller.signal.aborted || generation !== lifecycle.current) return;
      if (isAccessLost(cause)) {
        markAccessLost();
        return;
      }
      setConnectionError(cause instanceof Error ? cause.message : 'Unable to load shared files.');
    } finally {
      finishRequest(controller);
      refreshLock.current = false;
    }
  }, [room.id, room.status, createRequest, finishRequest, markAccessLost]);

  async function loadOlder() {
    if (!nextCursor || refreshLock.current) return;
    refreshLock.current = true;
    const generation = lifecycle.current;
    const controller = createRequest();
    try {
      const page = await api<FileListPage>(
        `/rooms/${room.id}/files?before=${encodeURIComponent(nextCursor)}`,
        'GET',
        undefined,
        controller.signal,
      );
      if (generation !== lifecycle.current || controller.signal.aborted) return;
      loadedOlderPages.current = true;
      const activeIds = new Set(page.activeIds);
      setFiles((current) => mergeFiles(current.filter((file) => activeIds.has(file.id)), page.files));
      setFileNames((current) => Object.fromEntries(Object.entries(current).filter(([id]) => activeIds.has(id))));
      setNextCursor(page.nextCursor);
    } catch (cause) {
      if (controller.signal.aborted || generation !== lifecycle.current) return;
      if (isAccessLost(cause)) {
        markAccessLost();
        return;
      }
      setConnectionError(cause instanceof Error ? cause.message : 'Unable to load older shared files.');
    } finally {
      finishRequest(controller);
      refreshLock.current = false;
    }
  }

  useEffect(() => {
    let active = true;
    const generation = lifecycle.current;
    const controller = createRequest();
    const fragmentRequest = ++fragmentGeneration.current;
    async function initialize() {
      setSecret(null);
      onKeyReady?.(null);
      setFiles([]);
      setFileNames({});
      setNextCursor(null);
      loadedOlderPages.current = false;
      setAccessUnavailable(false);
      if (room.status === 'closed' || room.status === 'expired') {
        setAvailable(false);
        return;
      }
      try {
        const fragment = readFilesFragment();
        setInvalid(fragment.invalid);
        if (fragment.invalid) {
          rejectActiveKey('The shared files key in this invitation is invalid.', true);
          return;
        }
        const serverKey = await api<{ fingerprint: string | null }>(
          `/rooms/${room.id}/files/key`,
          'GET',
          undefined,
          controller.signal,
        );
        if (!active || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
        setRegistered(serverKey.fingerprint);
        setAvailable(Boolean(serverKey.fingerprint) || room.role === 'owner');
        if (fragment.invalid) {
          setSecret(null);
          onKeyReady?.(null);
          setError('The shared files key in this invitation is invalid.');
          return;
        }

        const savedSecret = await loadRoomFileSecret(room.id);
        if (!active || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
        const candidate = fragment.secret ?? savedSecret;
        if (candidate) {
          const candidateFingerprint = await roomFileFingerprint(candidate);
          if (!active || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
          if (serverKey.fingerprint && serverKey.fingerprint !== candidateFingerprint) {
            rejectActiveKey('This browser has a different shared files key. Open the original room invitation to restore access.', false);
            return;
          }
          if (!active || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
          await saveRoomFileSecret(room.id, candidate);
          if (!active || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
          setSecret(candidate);
          if (fragment.secret) removeFilesFragment();
          onKeyReady?.(candidate);
        }

        if (room.status === 'open' && (serverKey.fingerprint || room.role === 'owner')) {
          await refresh();
          if (!active || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
          setPlans(await listRoomFilePlans(room.id));
        }
      } catch (cause) {
        if (controller.signal.aborted || generation !== lifecycle.current) return;
        if (isAccessLost(cause)) {
          setSecret(null);
          onKeyReady?.(null);
          setAvailable(false);
          setFiles([]);
          setFileNames({});
          setAccessUnavailable(true);
          return;
        }
        // An unavailable shared files feature does not affect the private inbox.
        setAvailable(room.role === 'owner');
      } finally {
        finishRequest(controller);
        if (active && generation === lifecycle.current) setInitialized(true);
      }
    }
    void initialize();
    return () => {
      active = false;
      controller.abort();
      finishRequest(controller);
      onKeyReady?.(null);
    };
  }, [room.id, room.role, room.status, refresh, onKeyReady, createRequest, finishRequest, rejectActiveKey]);

  useEffect(() => {
    if (room.status !== 'open') {
      setFiles([]);
      setFileNames({});
      setNextCursor(null);
      loadedOlderPages.current = false;
      activeController.current?.abort();
      return;
    }
    if (!secret) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      if (!active) return;
      if (document.visibilityState === 'visible' && navigator.onLine) await refresh();
      if (active && document.visibilityState === 'visible') {
        clearTimeout(timer);
        timer = setTimeout(() => void poll(), 5_000);
      }
    };
    const wake = () => {
      clearTimeout(timer);
      if (document.visibilityState === 'visible' && navigator.onLine) void poll();
    };
    void poll();
    document.addEventListener('visibilitychange', wake);
    window.addEventListener('focus', wake);
    window.addEventListener('online', wake);
    return () => {
      active = false;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', wake);
      window.removeEventListener('focus', wake);
      window.removeEventListener('online', wake);
    };
  }, [secret, refresh, room.status]);

  useEffect(() => {
    const restoreFromInvitation = () => {
      const generation = lifecycle.current;
      const fragmentRequest = ++fragmentGeneration.current;
      const fragment = readFilesFragment();
      if (fragment.invalid) {
        rejectActiveKey('The shared files key in this invitation is invalid.', true);
        return;
      }
      if (!fragment.secret) return;
      const controller = createRequest();
      void (async () => {
        try {
          const serverKey = await api<{ fingerprint: string | null }>(
            `/rooms/${room.id}/files/key`,
            'GET',
            undefined,
            controller.signal,
          );
          if (generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
          const fingerprint = await roomFileFingerprint(fragment.secret!);
          if (!serverKey.fingerprint || serverKey.fingerprint !== fingerprint) {
            rejectActiveKey('This invitation does not match the room’s registered shared files key.', false);
            return;
          }
          await saveRoomFileSecret(room.id, fragment.secret!);
          if (generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current || controller.signal.aborted) return;
          setSecret(fragment.secret);
          setRegistered(fingerprint);
          setInvalid(false);
          setError('');
          removeFilesFragment();
          onKeyReady?.(fragment.secret);
          await refresh();
        } catch (cause) {
          if (controller.signal.aborted || generation !== lifecycle.current || fragmentRequest !== fragmentGeneration.current) return;
          if (isAccessLost(cause)) {
            setSecret(null);
            onKeyReady?.(null);
            setFiles([]);
            setFileNames({});
            setAccessUnavailable(true);
          }
          setError(cause instanceof Error ? cause.message : 'Unable to restore shared file access.');
        } finally {
          finishRequest(controller);
        }
      })();
    };
    window.addEventListener('hashchange', restoreFromInvitation);
    return () => {
      window.removeEventListener('hashchange', restoreFromInvitation);
    };
  }, [room.id, refresh, onKeyReady, createRequest, finishRequest, rejectActiveKey]);

  useEffect(() => {
    if (!secret) return;
    let active = true;
    void Promise.all(
      files.map(async (file) => {
        try {
          const metadata = await decryptRoomFileDescriptor(
            room.id,
            file.id,
            file.descriptor,
            secret,
          );
          return [file.id, metadata.filename] as const;
        } catch {
          return [file.id, 'Unavailable file'] as const;
        }
      }),
    ).then((entries) => {
      if (active) setFileNames(Object.fromEntries(entries));
    });
    return () => {
      active = false;
    };
  }, [files, room.id, secret]);

  useEffect(
    () => () => activeController.current?.abort(),
    [room.id, room.status],
  );

  async function enableSharedFiles() {
    setBusy(true);
    setError('');
    try {
      const current = await api<{ fingerprint: string | null }>(
        `/rooms/${room.id}/files/key`,
      );
      const savedSecret = await loadRoomFileSecret(room.id);
      if (current.fingerprint && !savedSecret)
        throw new Error('Shared files already have a key for this room. Open the original room invitation to restore this browser’s key.');
      const candidate = savedSecret ?? crypto.getRandomValues(new Uint8Array(32));
      const fingerprint = await roomFileFingerprint(candidate);
      if (current.fingerprint && current.fingerprint !== fingerprint)
        throw new Error('This browser has a different shared files key. Open the original room invitation to restore access.');

      await saveRoomFileSecret(room.id, candidate);
      if (!current.fingerprint) {
        try {
          await api(`/rooms/${room.id}/files/key`, 'POST', { fingerprint });
        } catch (cause) {
          const check = await api<{ fingerprint: string | null }>(
            `/rooms/${room.id}/files/key`,
          );
          if (check.fingerprint !== fingerprint) throw cause;
        }
      }
      setSecret(candidate);
      setRegistered(fingerprint);
      onKeyReady?.(candidate);
      setStatus('Shared files enabled. Use an updated room link to share this key.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not enable shared files.');
    } finally {
      setBusy(false);
    }
  }

  async function prepareFile(file: File) {
    if (!secret || room.status !== 'open' || accessUnavailable) return;
    setBusy(true);
    setError('');
    try {
      await prepareRoomFile(file, room.id, secret);
      setPlans(await listRoomFilePlans(room.id));
      setStatus('Encrypted file is ready to share.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not prepare file.');
    } finally {
      setBusy(false);
    }
  }

  async function uploadPlan(plan: ReadyPlan) {
    if (!secret || room.status !== 'open' || accessUnavailable) return;
    const controller = new AbortController();
    activeController.current = controller;
    setProgress({ done: 0, total: plan.chunkCount });
    setBusy(true);
    setError('');
    try {
      const fingerprint = registered ?? (await roomFileFingerprint(secret));
      await uploadRoomFile(plan, fingerprint, controller.signal, (done, total) =>
        setProgress({ done, total }),
      );
      await clearRoomFilePlan(plan.id);
      setPlans(await listRoomFilePlans(room.id));
      await refresh();
      setStatus('File shared with admitted room participants.');
    } catch (cause) {
      if (!controller.signal.aborted)
        setError(cause instanceof Error ? cause.message : 'Upload failed; the encrypted copy remains saved in this browser.');
    } finally {
      if (activeController.current === controller) activeController.current = null;
      setBusy(false);
      setProgress(null);
    }
  }

  async function downloadFile(file: ListedFile) {
    if (!secret || accessUnavailable || room.status !== 'open') return;
    const controller = new AbortController();
    activeController.current = controller;
    setProgress({ done: 0, total: file.encryptedBytes });
    setBusy(true);
    setError('');
    try {
      await decryptRoomFileToDownload(
        room.id,
        file,
        secret!,
        async (index) => {
          const result = await retryRoomFileRequest(
            () => apiBytes(
              `/rooms/${room.id}/files/${file.id}/chunks/${index}`,
              'GET',
              undefined,
              controller.signal,
            ),
            controller.signal,
          );
          if (!/^[a-f0-9]{64}$/.test(result.sha256))
            throw new Error('The server returned an invalid encrypted chunk checksum.');
          return { bytes: result.bytes, sha256: result.sha256 };
        },
        (done, total) => setProgress({ done, total }),
        controller.signal,
      );
    } catch (cause) {
      if (!controller.signal.aborted && isAccessLost(cause)) {
        markAccessLost();
      } else if (!controller.signal.aborted) {
        setError(
          cause instanceof Error && cause.message
            ? cause.message
            : 'This shared file failed authentication. No download was saved.',
        );
      }
    } finally {
      if (activeController.current === controller) activeController.current = null;
      setBusy(false);
      setProgress(null);
    }
  }

  async function deleteFile(file: ListedFile) {
    if (accessUnavailable || room.status !== 'open') return;
    try {
      await api(`/rooms/${room.id}/files/${file.id}`, 'DELETE');
      setFiles((current) => current.filter((entry) => entry.id !== file.id));
      setFileNames((current) => {
        const next = { ...current };
        delete next[file.id];
        return next;
      });
      await refresh();
    } catch (cause) {
      if (isAccessLost(cause)) {
        markAccessLost();
        return;
      }
      setError(cause instanceof Error ? cause.message : 'Unable to delete file.');
    }
  }

  async function discardPlan(plan: ReadyPlan, localOnly = false) {
    if (!localOnly) {
      try {
        await api(`/rooms/${room.id}/files/${plan.id}`, 'DELETE');
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 404) {
          // No server record means only the local preparation needs removal.
        } else {
          if (isAccessLost(cause)) markAccessLost();
          setLocalDiscardPlan(plan.id);
          setError(cause instanceof Error ? cause.message : 'Unable to discard the server upload.');
          setStatus('Choose “Discard local copy only” if the server reservation cannot be reached.');
          return;
        }
      }
    } else if (!window.confirm('Discard this encrypted local copy only? Any server reservation may remain until cleanup.')) {
      return;
    }
    await clearRoomFilePlan(plan.id);
    setPlans(await listRoomFilePlans(room.id));
    setLocalDiscardPlan(null);
  }

  async function clearLocalDownloadCopies() {
    try {
      const removed = await clearRoomFileDownloadCopies();
      setLocalCopyCount(removed);
      setStatus(`${removed} local verified download ${removed === 1 ? 'copy was' : 'copies were'} removed.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to remove local download copies.');
    }
  }

  if (!initialized || !available) return null;
  return (
    <section className="panel room-files" aria-labelledby="room-files-heading">
      <h2 id="room-files-heading">Shared room files</h2>
      <p>
        Everyone admitted to this room can download these files. Room links contain the decryption
        key; share them only with trusted people. Removing access cannot retract files or keys
        already received.
      </p>
      {invalid && !error && <p role="alert" className="error">The shared files key in this invitation is invalid.</p>}
      {error && <p role="alert" className="error">{error}</p>}
      {connectionError && <p role="status" className="muted">{connectionError}</p>}
      {accessUnavailable && <p role="status">Shared file access is unavailable. The list will retry while this room remains open.</p>}
      {status && <p role="status">{status}</p>}
      {busy && progress && (
        <p role="status">
          Transfer progress: {progress.done.toLocaleString()} / {progress.total.toLocaleString()}{' '}
          <button className="secondary" onClick={() => activeController.current?.abort()}>
            Pause transfer
          </button>
        </p>
      )}
      {!secret ? (
        room.role === 'owner' ? (
          registered ? (
            <p>Shared files already have a key for this room. Open the original room invitation to restore this browser’s key.</p>
          ) : (
            <button disabled={busy} onClick={() => void enableSharedFiles()}>Enable shared files</button>
          )
        ) : (
          <p>Open the original room invitation to restore shared file access.</p>
        )
      ) : (
        <>
          <label className="file-select">
            <span>Choose file to share</span>
            <input
              type="file"
              aria-label="Choose file to share"
              disabled={busy || accessUnavailable || room.status !== 'open'}
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                if (file) void prepareFile(file);
                event.currentTarget.value = '';
              }}
            />
          </label>
          <p className="muted">Files are encrypted before upload. Maximum size: 250 MiB.</p>
          {room.status !== 'open' && <p role="status">File sharing is available while the room is open.</p>}
          {localCopyCount > 0 && <p role="status">{localCopyCount} local verified download {localCopyCount === 1 ? 'copy is' : 'copies are'} stored in this browser.</p>}
          <button className="secondary" type="button" onClick={() => void clearLocalDownloadCopies()}>
            Remove local verified download copies
          </button>
          {plans.map((plan) => (
            <div className="file-row" key={plan.id}>
              <span>
                {plan.filename} · {plan.size.toLocaleString()} bytes
                {plan.state === 'preparing' ? ' · interrupted preparation' : ''}
              </span>
              <button
                disabled={busy || accessUnavailable || room.status !== 'open' || plan.state !== 'ready'}
                onClick={() => void uploadPlan(plan)}
              >
                Share with room
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => void discardPlan(plan)}
              >
                Discard
              </button>
              {localDiscardPlan === plan.id && (
                <button className="secondary" onClick={() => void discardPlan(plan, true)}>
                  Discard local copy only
                </button>
              )}
            </div>
          ))}
          {files.map((file) => (
            <div className="file-row" key={file.id}>
              <span>
                {fileNames[file.id] ?? 'Reading encrypted filename…'} ·{' '}
                {new Date(file.createdAt).toLocaleString()}
              </span>
              <button disabled={busy || accessUnavailable || room.status !== 'open'} onClick={() => void downloadFile(file)}>
                Verify and download
              </button>
              {file.canDelete && (
                <button className="secondary" disabled={accessUnavailable} onClick={() => void deleteFile(file)}>
                  Delete
                </button>
              )}
            </div>
          ))}
          {nextCursor && (
            <button className="secondary" disabled={busy} onClick={() => void loadOlder()}>
              Load older files
            </button>
          )}
        </>
      )}
    </section>
  );
}
