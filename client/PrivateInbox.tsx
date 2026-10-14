import { useEffect, useState, type ChangeEvent } from 'react';
import { ApiError, api, apiBytes } from './api.js';
import { clearUpload, createKey, decryptSubmissionToDownload, digest, encodeBase64, encryptUploadChunk, exportEncryptedBackup, loadKey, loadUploadPlans, prepareSubmission, retainConfirmedKey, retainPendingKey, restoreEncryptedBackup, uploadManifest, type RecipientKeyPair, type UploadPlan } from './submissionCrypto.js';
import { decodeBase64 } from './submissionCrypto.js';
import type { Room } from '../shared/rooms.js';

interface KeyInfo { ownerPublicKey: string; ownerFingerprint: string; submitterFingerprint?: string | null }
interface Submission { id: string; descriptor: string; envelope: { enc: string; ciphertext: string }; chunkCount: number; encryptedBytes: number; manifestSha256: string; receipt: { acceptedAt: string; encryptedBytes: number; id: string; manifestSha256: string } }
interface SubmissionPage { submissions: Submission[]; nextCursor: string | null }
const pinnedKey = (roomId: string) => `portkey-organizer-key:${roomId}`;

async function retry<T>(work: () => Promise<T>) {
  for (let attempt = 0; ; attempt += 1) {
    try { return await work(); }
    catch (error) {
      const retryable = error instanceof ApiError ? error.status === 429 || error.status >= 500 : error instanceof TypeError;
      if (!retryable || attempt >= 5) throw error;
      const after = error instanceof ApiError ? error.retryAfterSeconds : 0;
      await new Promise(resolve => setTimeout(resolve, Math.max(after * 1000, Math.min(30_000, 1000 * 2 ** attempt))));
    }
  }
}

function saveTextFile(name: string, value: string) {
  const url = URL.createObjectURL(new Blob([value], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export function PrivateInbox({ room, onOwnerFingerprint }: { room: Room; onOwnerFingerprint?: (value: string | null) => void }) {
  const [keys, setKeys] = useState<KeyInfo | null>(null);
  const [pair, setPair] = useState<RecipientKeyPair | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [trusted, setTrusted] = useState(room.role === 'owner');
  const [needsExplicitTrust, setNeedsExplicitTrust] = useState(false);
  const [backupPassword, setBackupPassword] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [plans, setPlans] = useState<UploadPlan[]>([]);
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ sent: number; total: number } | null>(null);

  async function refreshSubmissions(cursor?: string | null) {
    const query = cursor ? `?before=${encodeURIComponent(cursor)}` : '';
    const page = await api<SubmissionPage>(`/rooms/${room.id}/submissions${query}`);
    setSubmissions(current => cursor ? [...current, ...page.submissions] : page.submissions);
    setNextCursor(page.nextCursor);
  }

  async function ensureParticipantKey(keyInfo: KeyInfo, saved: RecipientKeyPair | null) {
    if (keyInfo.submitterFingerprint) {
      if (!saved) { setMessage('Restore the encrypted backup for this browser’s registered key before retrieving submissions.'); return null; }
      if (saved.fingerprint !== keyInfo.submitterFingerprint) throw new Error('The browser key does not match its registered submission key.');
      setPair(saved); return saved;
    }
    const candidate = saved ?? await createKey();
    if (!saved) await retainPendingKey(room.id, candidate);
    const confirmed = await api<{ fingerprint: string }>(`/rooms/${room.id}/submissions/submitter-key`, 'POST', { publicKey: encodeBase64(candidate.publicKey) });
    if (confirmed.fingerprint !== candidate.fingerprint) throw new Error('The browser key registration did not match.');
    if (!saved) await retainConfirmedKey(room.id, candidate);
    setPair(candidate); return candidate;
  }

  async function loadState() {
    setLoading(true); setError('');
    try {
      const keyInfo = await api<KeyInfo>(`/rooms/${room.id}/submissions/keys`);
      setKeys(keyInfo);
      onOwnerFingerprint?.(room.role === 'owner' ? keyInfo.ownerFingerprint : null);
      const saved = await loadKey(room.id);
      let isTrusted = room.role === 'owner';
      if (saved && (room.role === 'owner' ? saved.fingerprint !== keyInfo.ownerFingerprint : keyInfo.submitterFingerprint && saved.fingerprint !== keyInfo.submitterFingerprint)) {
        setError('The browser’s saved key does not match the registered room key. Restore the matching encrypted backup.');
      } else if (saved) setPair(saved);
      if (room.role === 'participant') {
        const apiFingerprint = await digest(decodeBase64(keyInfo.ownerPublicKey));
        if (apiFingerprint !== keyInfo.ownerFingerprint) throw new Error('The organizer’s public key does not match its fingerprint.');
        const anchor = new URLSearchParams(window.location.hash.slice(1)).get('key');
        const localPin = localStorage.getItem(pinnedKey(room.id));
        if (anchor && anchor !== keyInfo.ownerFingerprint) throw new Error('This invitation key does not match the organizer’s registered key. Do not upload through this link.');
        if (localPin && localPin !== keyInfo.ownerFingerprint) throw new Error('The organizer’s key changed since this browser pinned it. Private submissions are blocked.');
        if (anchor === keyInfo.ownerFingerprint) {
          localStorage.setItem(pinnedKey(room.id), keyInfo.ownerFingerprint);
          isTrusted = true;
        } else if (localPin === keyInfo.ownerFingerprint) isTrusted = true;
        else setNeedsExplicitTrust(true);
        setTrusted(isTrusted);
        if (isTrusted) await ensureParticipantKey(keyInfo, saved);
      }
      if (room.role === 'owner' && saved && saved.fingerprint === keyInfo.ownerFingerprint) setPair(saved);
      const pending = await loadUploadPlans(room.id);
      setPlans(pending);
      if (room.status === 'open' && (room.role === 'owner' ? saved?.fingerprint === keyInfo.ownerFingerprint : isTrusted && (saved?.fingerprint === keyInfo.submitterFingerprint || !keyInfo.submitterFingerprint))) {
        await refreshSubmissions();
      }
    } catch (cause) {
      if (!(cause instanceof ApiError && cause.status === 409 && cause.code === 'INBOX_NOT_ENABLED')) setError(cause instanceof Error ? cause.message : 'Unable to load the encrypted inbox.');
      else { setKeys(null); onOwnerFingerprint?.(null); }
    } finally { setLoading(false); }
  }

  useEffect(() => { void loadState(); }, [room.id, room.role]);

  async function enableInbox() {
    setBusy(true); setError('');
    try {
      const candidate = await loadKey(room.id) ?? await createKey();
      await retainPendingKey(room.id, candidate);
      const confirmation = await api<{ fingerprint: string }>(`/rooms/${room.id}/submissions/owner-key`, 'POST', { publicKey: encodeBase64(candidate.publicKey) });
      if (confirmation.fingerprint !== candidate.fingerprint) throw new Error('The registered organizer key did not match.');
      await retainConfirmedKey(room.id, candidate);
      setPair(candidate);
      setKeys({ ownerPublicKey: encodeBase64(candidate.publicKey), ownerFingerprint: candidate.fingerprint });
      onOwnerFingerprint?.(candidate.fingerprint);
      setMessage('Encrypted inbox enabled. Download and store the recovery backup before inviting submissions.');
      if (room.status === 'open') await refreshSubmissions();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not enable the inbox.'); }
    finally { setBusy(false); }
  }

  async function restoreBackup(event: ChangeEvent<HTMLInputElement>) {
    const backup = event.target.files?.[0];
    if (!backup || !keys) return;
    setBusy(true); setError('');
    try {
      if (backup.size > 32_768) throw new Error('The encrypted key backup is too large.');
      const text = await backup.text();
      const restored = await restoreEncryptedBackup(room.id, text, backupPassword, room.role === 'owner' ? keys.ownerFingerprint : keys.submitterFingerprint ?? '');
      setPair(restored); setMessage('The backup key matches the registered room key.');
      if (room.role === 'owner') await refreshSubmissions();
      else if (trusted) { await ensureParticipantKey(keys, restored); await refreshSubmissions(); }
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not restore the encrypted key backup.'); }
    finally { setBusy(false); event.target.value = ''; }
  }

  async function downloadBackup() {
    if (!pair) return;
    try { saveTextFile(`portkey-${room.id}-key-backup.json`, await exportEncryptedBackup(room.id, pair, backupPassword)); setMessage('Encrypted key backup downloaded.'); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not create the key backup.'); }
  }

  async function transfer(plan: UploadPlan, source: File | null) {
    setBusy(true); setError(''); setMessage('');
    try {
      const started = await retry(() => api<{ complete: boolean; receipt?: Submission['receipt'] }>(`/rooms/${room.id}/submissions`, 'POST', { uploadId: plan.objectId }));
      if (started.complete && started.receipt) {
        await clearUpload(plan.objectId);
        setPlans(current => current.filter(item => item.objectId !== plan.objectId));
        setProgress(null);
        setMessage(`Submission accepted at ${new Date(started.receipt.acceptedAt).toLocaleString()}. Receipt: ${started.receipt.id}`);
        try { await refreshSubmissions(); } catch { setError('The submission was accepted, but the inbox list could not be refreshed.'); }
        return;
      }
      await retry(() => api(`/rooms/${room.id}/submissions/${plan.objectId}/metadata`, 'PUT', { descriptor: plan.descriptor, ownerEnvelope: plan.ownerEnvelope, submitterEnvelope: plan.submitterEnvelope }));
      let sent = 0;
      setProgress({ sent, total: plan.fileSize });
      for (let index = 0; index < plan.chunkSizes.length; index += 1) {
        const encrypted = await encryptUploadChunk(source, plan, index);
        await retry(() => apiBytes(`/rooms/${room.id}/submissions/${plan.objectId}/chunks/${index}`, 'PUT', encrypted));
        sent += plan.chunkSizes[index]; setProgress({ sent, total: plan.fileSize });
      }
      const manifestSha256 = await uploadManifest(plan);
      const completed = await retry(() => api<{ receipt: Submission['receipt'] }>(`/rooms/${room.id}/submissions/${plan.objectId}/complete`, 'POST', { chunkCount: plan.chunkSizes.length, manifestSha256 }));
      await clearUpload(plan.objectId);
      setPlans(current => current.filter(item => item.objectId !== plan.objectId));
      setProgress(null);
      setMessage(`Submission accepted at ${new Date(completed.receipt.acceptedAt).toLocaleString()}. Receipt: ${completed.receipt.id}`);
      try { await refreshSubmissions(); } catch { setError('The submission was accepted, but the inbox list could not be refreshed.'); }
    } catch (cause) {
      setProgress(null);
      setError(cause instanceof Error ? `${cause.message} The encrypted upload is saved locally for retry.` : 'The upload did not complete. Its encrypted data is saved locally for retry.');
      setPlans(await loadUploadPlans(room.id));
    } finally { setBusy(false); }
  }

  async function startUpload() {
    if (!file || !keys || !pair) return;
    if (file.size > 262144000) { setError('The file exceeds the 250 MiB limit.'); return; }
    setBusy(true); setError('');
    try {
      const objectId = crypto.randomUUID();
      const plan = await prepareSubmission(file, room.id, objectId, decodeBase64(keys.ownerPublicKey), keys.ownerFingerprint, pair);
      setPlans(current => [...current, plan]);
      await transfer(plan, file);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not prepare this file.'); }
    finally { setBusy(false); }
  }

  async function discard(plan: UploadPlan) {
    setBusy(true); setError('');
    try { await api(`/rooms/${room.id}/submissions/${plan.objectId}`, 'DELETE'); await clearUpload(plan.objectId); setPlans(current => current.filter(item => item.objectId !== plan.objectId)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not discard the incomplete upload.'); }
    finally { setBusy(false); }
  }

  async function download(item: Submission) {
    if (!pair) return;
    setBusy(true); setError('');
    try {
      await decryptSubmissionToDownload(room.id, item, pair, async index => {
        const result = await retry(() => apiBytes(`/rooms/${room.id}/submissions/${item.id}/chunks/${index}`));
        return { bytes: result.bytes, sha256: result.sha256 };
      }, (read, total) => setProgress({ sent: read, total }));
      setMessage('File integrity verified and download saved.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not decrypt this submission.'); }
    finally { setBusy(false); setProgress(null); }
  }

  if (loading) return <section className="panel"><p role="status">Loading encrypted inbox…</p></section>;
  const owner = room.role === 'owner';
  return (
    <section className="panel private-inbox" aria-labelledby={`inbox-${room.id}`}>
      <div className="panel-heading"><div><p className="eyebrow">PRIVATE FILES</p><h2 id={`inbox-${room.id}`}>Encrypted submission inbox</h2><p>Files and filenames are encrypted in this browser before transfer.</p></div></div>
      {error && <p role="alert" className="error">{error}</p>}
      {message && <p role="status" className="muted">{message}</p>}
      {owner && !keys && <div><p>Enable the inbox to create and register an organizer decryption key in this browser.</p><button disabled={busy || ['closed', 'expired'].includes(room.status)} onClick={() => void enableInbox()}>Enable encrypted inbox</button></div>}
      {keys && !pair && (owner || keys.submitterFingerprint) && <div className="backup-controls"><p>The registered private key is not stored in this browser. Restore its encrypted backup to access submissions.</p><label>Backup passphrase<input type="password" autoComplete="current-password" value={backupPassword} onChange={event => setBackupPassword(event.target.value)} /></label><label>Encrypted key backup<input type="file" accept="application/json,.json" onChange={event => void restoreBackup(event)} /></label></div>}
      {pair && <div className="backup-controls"><p>{owner ? 'Organizer' : 'Submitter'} key fingerprint: <code>{pair.fingerprint}</code></p><label>Backup passphrase<input type="password" autoComplete="new-password" value={backupPassword} onChange={event => setBackupPassword(event.target.value)} placeholder="At least 12 characters" /></label><button className="secondary" disabled={busy || backupPassword.length < 12} onClick={() => void downloadBackup()}>Download encrypted key backup</button><p className="muted">A backup restores the decryption key, but does not restore this browser’s room access.</p></div>}
      {!owner && keys && needsExplicitTrust && <div className="notice"><p>Invitation has no organizer-key fingerprint. Compare this fingerprint with the organizer through a trusted channel before enabling submissions.</p><code>{keys.ownerFingerprint}</code><button disabled={busy} onClick={() => { localStorage.setItem(pinnedKey(room.id), keys.ownerFingerprint); setTrusted(true); setNeedsExplicitTrust(false); void ensureParticipantKey(keys, pair).then(restored => restored && refreshSubmissions()).catch(cause => setError(cause.message)); }}>I verified this fingerprint with the organizer</button></div>}
      {!owner && keys && trusted && pair && room.status === 'open' && <div className="upload-controls"><label>Choose a file (up to 250 MiB)<input type="file" onChange={event => setFile(event.target.files?.[0] ?? null)} /></label><button disabled={busy || !file} onClick={() => void startUpload()}>{busy ? 'Encrypting and uploading…' : 'Submit file privately'}</button></div>}
      {!owner && !trusted && <p role="note">Private upload is blocked until the organizer’s key is verified.</p>}
      {plans.length > 0 && <div><h3>Interrupted uploads</h3>{plans.map(plan => <div className="actions" key={plan.objectId}><span>{(plan.fileSize / 1024 / 1024).toFixed(1)} MiB · {plan.chunkSizes.length} chunks</span><button disabled={busy} onClick={() => void transfer(plan, file)}>{file ? 'Resume with selected file' : 'Retry saved encrypted chunks'}</button><button className="secondary" disabled={busy} onClick={() => void discard(plan)}>Discard</button></div>)}</div>}
      {progress && <div role="status"><progress value={progress.sent} max={Math.max(progress.total, 1)} /> {progress.total ? `${Math.round(progress.sent / progress.total * 100)}%` : 'Verifying zero-byte file'}</div>}
      {pair && (owner || trusted) && <div className="submission-list"><h3>{owner ? 'Received submissions' : 'Your submissions'}</h3>{owner && room.status === 'open' && <button className="secondary" disabled={busy} onClick={() => void refreshSubmissions().catch(cause => setError(cause.message))}>Refresh inbox</button>}{submissions.length === 0 ? <p>No completed submissions yet.</p> : <ul>{submissions.map(item => <li key={item.id}><span>{new Date(item.receipt.acceptedAt).toLocaleString()} · {(item.receipt.encryptedBytes / 1024 / 1024).toFixed(1)} MiB encrypted</span><button className="secondary" disabled={busy} onClick={() => void download(item)}>Decrypt and download</button></li>)}</ul>}{nextCursor && <button className="secondary" onClick={() => void refreshSubmissions(nextCursor).catch(cause => setError(cause.message))}>Load older submissions</button>}</div>}
    </section>
  );
}
