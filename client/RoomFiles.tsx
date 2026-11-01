import { useEffect, useRef, useState, type ChangeEvent } from 'react';
import { saveUpload, pendingUploads, forgetUpload, immutableUploadChunk } from './uploadStore.js';
import { ApiError, api, apiBytes } from './api.js';
import {
  clearLocalDownloadCopies, createKey, decodeBase64, decryptRoomFileToDownload,
  digest, distributionManifest, encodeBase64, exportEncryptedBackup,
  loadKey, loadRegisteredKey, replaceStoredKey, rewrapFileKey, roomFileName,
  prepareDistribution, retainConfirmedKey, restoreEncryptedBackup,
  deriveRoomAccessKey, encodeRoomAccess, decodeRoomAccess, roomAccessStorageId, shareExistingFile,
  type DistributionPlan, type RecipientKeyPair,
} from './roomCrypto.js';
import type { Room } from '../shared/rooms.js';

interface RoomKeys {
  ownerPublicKey: string; ownerFingerprint: string; ownerRecipientId?: string;
  recipientFingerprint?: string | null;
  roomAccessPublicKey?: string | null; roomAccessFingerprint?: string | null;
  recipients?: { id: string; label: string; publicKey: string; fingerprint: string }[];
}
interface RoomFile {
  id: string; descriptor: string; envelope: { enc: string; ciphertext: string };
  envelopeKind?: 'room' | 'personal'; roomShared?: boolean;
  chunkCount: number; encryptedBytes: number; manifestSha256: string;
  receipt: { acceptedAt: string; encryptedBytes: number; id: string; manifestSha256: string };
}
interface FilePage { files: RoomFile[]; nextCursor: string | null }
const pinnedKey = (roomId: string) => `portkey-organizer-key:${roomId}`;

export function RoomFiles({ room, onOwnerFingerprint, onRoomAccess }: {
  room: Room; onOwnerFingerprint?: (value: string | null) => void;
  onRoomAccess?: (value: string | null) => void;
}) {
  const owner = room.role === 'owner';
  const inactive = room.status !== 'open';
  const [keys, setKeys] = useState<RoomKeys | null>(null);
  const [pair, setPair] = useState<RecipientKeyPair | null>(null);
  const [roomAccess, setRoomAccess] = useState<RecipientKeyPair | null>(null);
  const [files, setFiles] = useState<RoomFile[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [message, setMessage] = useState('');
  const [progress, setProgress] = useState<{ sent: number; total: number } | null>(null);
  const [pending, setPending] = useState<DistributionPlan[]>([]);
  const [file, setFile] = useState<File | null>(null), [backupPassword, setBackupPassword] = useState('');
  const [invitationHash, setInvitationHash] = useState(window.location.hash);
  const transferController = useRef<AbortController | null>(null);
  const initialization = useRef<Promise<void> | null>(null);
  const generation = useRef(0), browsingOlder = useRef(false);
  const usableKey = owner ? pair : roomAccess ?? pair;

  async function filePage(cursor?: string | null): Promise<FilePage> {
    return api(`/rooms/${room.id}/files${cursor ? `?before=${encodeURIComponent(cursor)}` : ''}`);
  }
  async function refreshFiles(cursor?: string | null) {
    const page = await filePage(cursor);
    browsingOlder.current = Boolean(cursor);
    setFiles(current => cursor ? [...current, ...page.files] : page.files);
    setNextCursor(page.nextCursor);
  }
  async function allFiles() {
    const result: RoomFile[] = []; let cursor: string | null = null;
    do { const page = await filePage(cursor); result.push(...page.files); cursor = page.nextCursor; } while (cursor);
    return result;
  }
  async function initializeOwner() {
    if (!initialization.current) initialization.current = (async () => {
      const candidate = await loadKey(room.id) ?? await createKey();
      await retainConfirmedKey(room.id, candidate);
      const confirmed = await api<{fingerprint: string}>(`/rooms/${room.id}/keys/owner`, 'POST', { publicKey: encodeBase64(candidate.publicKey) });
      if (confirmed.fingerprint !== candidate.fingerprint) throw new Error('Room encryption setup did not match.');
    })().finally(() => { initialization.current = null; });
    await initialization.current;
  }
  async function loadState() {
    const requestGeneration = ++generation.current;
    const current = () => generation.current === requestGeneration;
    setLoading(true); setError(''); setPair(null); setRoomAccess(null); setFiles([]); setNextCursor(null);
    if (owner) { onOwnerFingerprint?.(null); onRoomAccess?.(null); }
    try {
      if (owner) setPending(await pendingUploads(room.id));
      let info: RoomKeys;
      try { info = await api(`/rooms/${room.id}/files/keys`); }
      catch (cause) {
        if (!(owner && ['draft', 'open'].includes(room.status) && cause instanceof ApiError && cause.code === 'KEYS_NOT_READY')) throw cause;
        await initializeOwner(); info = await api(`/rooms/${room.id}/files/keys`);
      }
      if (!current()) return;
      setKeys(info);
      if (await digest(decodeBase64(info.ownerPublicKey)) !== info.ownerFingerprint) throw new Error('Room verification failed. Ask the organizer for a fresh invitation.');
      const saved = await loadRegisteredKey(room.id, owner ? info.ownerFingerprint : info.recipientFingerprint ?? '');
      let personal: RecipientKeyPair | null = null, access: RecipientKeyPair | null = null;
      if (owner) {
        if (!saved || saved.fingerprint !== info.ownerFingerprint) {
          if (current()) { setPair(null); setRoomAccess(null); onOwnerFingerprint?.(null); onRoomAccess?.(null); }
          throw new Error('Restore your organizer backup under Security and recovery to share or download files in this browser.');
        }
        personal = saved;
        access = await loadKey(roomAccessStorageId(room.id)) ?? await deriveRoomAccessKey(saved, room.id);
        if (info.roomAccessFingerprint && access.fingerprint !== info.roomAccessFingerprint) throw new Error('Restore the latest organizer backup to recover room access.');
        await retainConfirmedKey(roomAccessStorageId(room.id), access);
        if (!info.roomAccessFingerprint) {
          await api(`/rooms/${room.id}/keys/room-access`, 'POST', { publicKey: encodeBase64(access.publicKey) });
          info = { ...info, roomAccessPublicKey: encodeBase64(access.publicKey), roomAccessFingerprint: access.fingerprint };
        }
        if (room.status === 'open') {
          const previous = (await allFiles()).filter(item => !item.roomShared);
          if (previous.length) {
            const envelopes = await Promise.all(previous.map(async item => ({ fileId: item.id, ...await shareExistingFile(room.id, item, saved, access!.publicKey) })));
            await api(`/rooms/${room.id}/files/room-access`, 'POST', { fingerprint: access.fingerprint, envelopes: envelopes.map(({fileId, enc, ciphertext}) => ({fileId, enc, ciphertext})) });
          }
        }
      } else if (info.roomAccessFingerprint) {
        const invitation = new URLSearchParams(window.location.hash.slice(1)).get('access');
        access = invitation ? await decodeRoomAccess(invitation) : await loadKey(roomAccessStorageId(room.id));
        if (!access || access.fingerprint !== info.roomAccessFingerprint) throw new Error('Open the organizer’s current invitation or scan the room QR again to load your files.');
        await retainConfirmedKey(roomAccessStorageId(room.id), access);
      } else {
        // Compatibility for an older room until its organizer opens it once.
        const anchor = new URLSearchParams(window.location.hash.slice(1)).get('key');
        const pin = localStorage.getItem(pinnedKey(room.id));
        if ((anchor && anchor !== info.ownerFingerprint) || (pin && pin !== info.ownerFingerprint && anchor !== info.ownerFingerprint)) throw new Error('Room verification changed. Open a fresh organizer invitation.');
        localStorage.setItem(pinnedKey(room.id), info.ownerFingerprint);
        personal = saved ?? await createKey();
        if (info.recipientFingerprint && personal.fingerprint !== info.recipientFingerprint) throw new Error('Restore your browser backup under Security and recovery.');
        await retainConfirmedKey(room.id, personal);
        await api(`/rooms/${room.id}/keys/participant`, 'POST', { publicKey: encodeBase64(personal.publicKey) });
      }
      if (!current()) return;
      setKeys(info); setPair(personal); setRoomAccess(access);
      if (owner) { onOwnerFingerprint?.(info.ownerFingerprint); onRoomAccess?.(access ? encodeRoomAccess(access) : null); }
      if (room.status === 'open') await refreshFiles();
    } catch (cause) {
      if (current()) setError(cause instanceof Error ? cause.message : 'Unable to prepare room files.');
    } finally { if (current()) setLoading(false); }
  }
  useEffect(() => { void loadState(); return () => { generation.current++; }; }, [room.id, room.role, room.status, invitationHash]);
  useEffect(() => {
    const changed = () => { transferController.current?.abort(); setInvitationHash(window.location.hash); };
    window.addEventListener('hashchange', changed);
    return () => { window.removeEventListener('hashchange', changed); transferController.current?.abort(); };
  }, []);
  useEffect(() => { if (inactive) transferController.current?.abort(); }, [inactive]);
  useEffect(() => {
    if (inactive || !usableKey || busy) return;
    const timer = setInterval(() => {
      if (!browsingOlder.current) void refreshFiles().catch(cause => setError(cause.message));
    }, 5000);
    return () => clearInterval(timer);
  }, [room.id, room.status, usableKey, busy]);
  useEffect(() => {
    let active = true;
    void Promise.all(files.map(async item => {
      const key = item.envelopeKind === 'room' ? roomAccess : pair;
      if (!key) return;
      try { const name = await roomFileName(room.id, item, key); if (active) setNames(current => ({ ...current, [item.id]: name })); }
      catch { if (active) setNames(current => ({ ...current, [item.id]: 'Unable to read file name' })); }
    }));
    return () => { active = false; };
  }, [files, pair, roomAccess, room.id]);

  async function rotateKey() {
    if (!owner || !pair) return;
    setBusy(true); setError('');
    try {
      const candidate = await createKey();
      await retainConfirmedKey(`${room.id}:key:${candidate.fingerprint}`, candidate);
      const records = await allFiles();
      const envelopes = await Promise.all(records.map(async item => ({ fileId: item.id, ...await rewrapFileKey(room.id, item, pair, candidate.publicKey) })));
      await api(`/rooms/${room.id}/keys/rotate`, 'POST', { publicKey: encodeBase64(candidate.publicKey), expectedFingerprint: pair.fingerprint, envelopes });
      await replaceStoredKey(room.id, candidate); await loadState();
      setMessage('Organizer key replaced. Export a fresh recovery backup. Student file access is unchanged.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Key replacement failed.'); }
    finally { setBusy(false); }
  }
  async function restoreBackup(event: ChangeEvent<HTMLInputElement>) {
    const backup = event.target.files?.[0]; if (!backup || !keys) return;
    setBusy(true); setError('');
    try {
      if (backup.size > 32768) throw new Error('The encrypted backup is too large.');
      const sharedStudent = !owner && Boolean(keys.roomAccessFingerprint);
      await restoreEncryptedBackup(room.id, await backup.text(), backupPassword,
        owner ? keys.ownerFingerprint : keys.roomAccessFingerprint ?? keys.recipientFingerprint ?? '',
        { storageId: sharedStudent ? roomAccessStorageId(room.id) : room.id, roomAccessFingerprint: keys.roomAccessFingerprint });
      setBackupPassword(''); await loadState(); setMessage(owner ? 'The organizer key was restored from its backup.' : 'Your room access was restored.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not restore the backup.'); }
    finally { setBusy(false); event.target.value = ''; }
  }
  async function downloadBackup() {
    const backupKey = owner ? pair : roomAccess ?? pair; if (!backupKey) return;
    try {
      const url = URL.createObjectURL(new Blob([await exportEncryptedBackup(room.id, backupKey, backupPassword, owner ? roomAccess ?? undefined : undefined)], { type: 'application/json' }));
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `portkey-${room.id}-key-backup.json`; anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000); setBackupPassword(''); setMessage('Encrypted recovery backup downloaded. Keep it and its passphrase safe.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not create the backup.'); }
  }
  async function publish(resume?: DistributionPlan) {
    if (!file && !resume) return;
    if (resume?.sourceMissing) { setError('Browser storage removed the saved source. Discard this upload and select the file again.'); return; }
    setBusy(true);
    setError('');
    setMessage('');
    setProgress({ sent: 0, total: resume?.fileSize ?? file!.size });
    const controller = new AbortController();
    transferController.current = controller;
    const fileId = resume?.fileId ?? crypto.randomUUID();
    let complete = false;
    try {
      // Recheck registered keys before publishing or resuming a saved plan.
      const current = await api<RoomKeys>(`/rooms/${room.id}/files/keys`);
      setKeys(current);
      if (!pair || !roomAccess || !current.ownerRecipientId)
        throw new Error(
          'This browser does not have the room key yet. Reload the page and try again.',
        );
      const recipients = [
        { id: current.ownerRecipientId, publicKey: pair.publicKey },
      ];
      const currentFingerprints = new Map<string, string>([
        [current.ownerRecipientId, current.ownerFingerprint],
        ...(current.recipients ?? []).map(recipient => [recipient.id, recipient.fingerprint] as [string, string]),
      ]);
      if (pair.fingerprint !== current.ownerFingerprint) throw new Error('The organizer key changed. Reload before publishing.');
      if (resume && (resume.roomEnvelope?.fingerprint !== roomAccess.fingerprint || !resume.recipientFingerprints || Object.entries(resume.recipientFingerprints).some(([id, fingerprint]) => currentFingerprints.get(id) !== fingerprint))) {
        throw new Error('Recipient keys or approval changed. Discard this saved upload and select the file again to seal a fresh plan.');
      }
      controller.signal.throwIfAborted();
      const plan: DistributionPlan = resume ?? await prepareDistribution(
        file!,
        room.id,
        fileId,
        recipients,
        roomAccess.publicKey,
      );
      if (!resume) await saveUpload(plan);
      setPending(await pendingUploads(room.id));
      const started = await api<{ complete: boolean }>(`/rooms/${room.id}/files`, 'POST', { fileId }, controller.signal);
      if (started.complete) { complete = true; await forgetUpload(plan); await refreshFiles(); setMessage('The previous upload was already accepted.'); return; }
      await api(`/rooms/${room.id}/files/${fileId}/metadata`, 'PUT', {
        descriptor: plan.descriptor,
        envelopes: plan.envelopes,
        recipientFingerprints: plan.recipientFingerprints,
        roomEnvelope: plan.roomEnvelope,
      }, controller.signal);
      const digests: string[] = [];
      let sent = 0;
      const total = plan.chunkSizes.reduce((sum, size) => sum + size + 16, 0);
      for (let index = 0; index < plan.chunkSizes.length; index += 1) {
        controller.signal.throwIfAborted();
        const chunk = await immutableUploadChunk(plan, index);
        const result = await apiBytes(
          `/rooms/${room.id}/files/${fileId}/chunks/${index}`,
          'PUT',
          chunk.ciphertext,
          controller.signal,
        );
        if (result.sha256 !== chunk.sha256)
          throw new Error('The server stored a different encrypted chunk.');
        digests.push(chunk.sha256);
        sent += chunk.ciphertext.length;
        setProgress({ sent, total });
      }
      const manifestSha256 = await distributionManifest(plan, digests);
      await api(`/rooms/${room.id}/files/${fileId}/complete`, 'POST', {
        chunkCount: plan.chunkSizes.length,
        manifestSha256,
      }, controller.signal);
      complete = true;
      await forgetUpload(plan);
      setMessage(
        `Published “${plan.file.name}” to the room. All approved members can download it.`,
      );
      setFile(null);
      await refreshFiles();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : 'Could not publish the file.',
      );
    } finally {
      // Keep the local journal, but reclaim the remote incomplete-upload slot;
      // the stale-upload worker handles failures after closure or disconnection.
      if (!complete) await api(`/rooms/${room.id}/files/${fileId}?incompleteOnly=true`, 'DELETE').catch(() => undefined);
      setPending(await pendingUploads(room.id));
      transferController.current = null;
      setProgress(null);
      setBusy(false);
    }
  }


  async function download(item: RoomFile) {
    const key = item.envelopeKind === 'room' ? roomAccess : pair;
    if (!key) { setError('Open the organizer invitation again to restore file access.'); return; }
    const controller = new AbortController(); transferController.current = controller;
    setBusy(true); setError(''); setMessage('');
    try {
      await decryptRoomFileToDownload(room.id, item, key, async index => {
        const response = await apiBytes(`/rooms/${room.id}/files/${item.id}/chunks/${index}`, 'GET', undefined, controller.signal);
        return { bytes: response.bytes, sha256: response.sha256 };
      }, (sent, total) => setProgress({ sent, total }));
      setMessage('File verified and saved.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not download the file.'); }
    finally { transferController.current = null; setProgress(null); setBusy(false); }
  }
  async function removeDownloadCopies() {
    setBusy(true);
    try { const count = await clearLocalDownloadCopies(); setMessage(`${count} local download copies removed.`); }
    catch { setError('Could not remove local download copies.'); }
    finally { setBusy(false); }
  }
  if (loading) return <section className="panel"><p role="status">Preparing room files…</p></section>;
  const canPublish = owner && pair?.fingerprint === keys?.ownerFingerprint && roomAccess !== null;
  return <section className="panel room-files" aria-labelledby={`files-${room.id}`}>
    <div className="panel-heading"><div>
      <h2 id={`files-${room.id}`}>{owner ? 'Room file sharing' : 'Files from your organizer'}</h2>
      <p>{owner ? 'Files you share here are available to every approved member, including people who join later.' : 'All room files are available once you are admitted. Downloads are decrypted automatically in this browser.'}</p>
    </div></div>
    {error && <p role="alert" className="error">{error}</p>}
    {message && <p role="status" className="muted">{message}</p>}
    {progress && <p role="status"><progress value={progress.sent} max={Math.max(progress.total, 1)} /> {Math.round(progress.sent / Math.max(progress.total, 1) * 100)}%</p>}
    {busy && transferController.current && <button className="secondary" onClick={() => transferController.current?.abort()}>Cancel transfer</button>}
    {inactive && <p role="note">{room.status === 'draft' ? 'Open the room to share files.' : 'This room is no longer open.'}</p>}
    {owner && canPublish && !inactive && <div className="upload-controls">
      <label>Choose a file (up to 250 MiB)<input type="file" onChange={event => setFile(event.target.files?.[0] ?? null)} /></label>
      <button disabled={busy || !file} onClick={() => void publish()}>{busy ? 'Sharing…' : 'Encrypt and share with room'}</button>
    </div>}
    {owner && pending.length > 0 && <div className="notice"><h3>Saved uploads</h3>
      <p>Retry uses the saved local file and encrypted chunks. Discard removes the saved upload from this browser.</p>
      {pending.map(plan => <div className="actions" key={plan.fileId}>
        <span>{plan.file.name}</span>
        <button disabled={busy || inactive} onClick={() => void publish(plan)}>Resume upload</button>
        <button className="secondary" disabled={busy} onClick={() => void (async () => {
          await api(`/rooms/${room.id}/files/${plan.fileId}?incompleteOnly=true`, 'DELETE').catch(() => undefined);
          await forgetUpload(plan); setPending(await pendingUploads(room.id));
        })().catch(cause => setError(cause.message))}>Discard saved upload</button>
      </div>)}
    </div>}
    {usableKey && !inactive && <div className="submission-list">
      <h3>{owner ? 'Shared files' : 'Files shared with you'}</h3>
      <button className="secondary" disabled={busy} onClick={() => void refreshFiles().catch(cause => setError(cause.message))}>Refresh files</button>
      {files.length === 0 ? <p>No shared files yet. Files appear here automatically when the organizer shares them.</p> : <ul>{files.map(item => <li key={item.id}>
        <span><strong>{names[item.id] ?? 'Loading file name…'}</strong> · {(item.encryptedBytes / 1048576).toFixed(1)} MiB</span>
        <button disabled={busy || !(item.envelopeKind === 'room' ? roomAccess : pair)} onClick={() => void download(item)}>Download</button>
        {owner && <button className="secondary" disabled={busy} onClick={() => { if (window.confirm('Delete this file for everyone? Saved copies cannot be removed.')) void api(`/rooms/${room.id}/files/${item.id}`, 'DELETE').then(() => refreshFiles()).catch(cause => setError(cause.message)); }}>Delete published file</button>}
      </li>)}</ul>}
      {nextCursor && <button className="secondary" disabled={busy} onClick={() => void refreshFiles(nextCursor).catch(cause => setError(cause.message))}>Load older files</button>}
    </div>}
    <details className="backup-controls security-settings" open={owner && keys && !pair ? true : undefined}>
      <summary>Security and recovery (optional)</summary>
      <p>Encryption and access checks run automatically. These tools are only for recovery or replacing an organizer key.</p>
      {keys && <p className="muted">Organizer verification fingerprint: <code>{keys.ownerFingerprint}</code></p>}
      {keys?.roomAccessFingerprint && <p className="muted">Room access verification fingerprint: <code>{keys.roomAccessFingerprint}</code></p>}
      {keys && <>
        <label>Backup passphrase<input type="password" autoComplete="new-password" value={backupPassword} onChange={event => setBackupPassword(event.target.value)} placeholder="At least 12 characters" /></label>
        {usableKey && <button className="secondary" disabled={busy || backupPassword.length < 12} onClick={() => void downloadBackup()}>Download encrypted key backup</button>}
        <label>Restore key backup (.json)<input type="file" accept="application/json,.json" onChange={event => void restoreBackup(event)} /></label>
      </>}
      {owner && pair && !inactive && <button className="secondary" disabled={busy || pending.length > 0} onClick={() => void rotateKey()}>Rotate encryption key</button>}
      <button className="secondary" disabled={busy} onClick={() => void removeDownloadCopies()}>Remove local download copies</button>
    </details>
  </section>;
}
