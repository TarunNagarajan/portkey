import { useState } from 'react';
import { api } from './api.js';
export function OwnerRecovery({ roomId }: { roomId: string }) {
  const [code, setCode] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  return <section className="panel"><h2>Ownership recovery</h2>
    <p>Store a recovery code separately from your encrypted key backup. Anyone holding this code can take ownership. Creating a new code invalidates the previous one.</p>
    <button disabled={busy} onClick={() => void (async () => {
      setBusy(true); setError('');
      try { const result = await api<{ recoveryCode: string }>(`/rooms/${roomId}/recovery`, 'POST'); setCode(result.recoveryCode); }
      catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not create code.'); }
      finally { setBusy(false); }
    })()}>Create ownership recovery code</button>
    {code && <div role="status"><p>Save this code now. It works once at the recovery page.</p><code>{code}</code><p><a href="/recover">Open recovery page</a></p><button className="secondary" onClick={() => setCode('')}>Hide code</button></div>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
export function RecoverRoom() {
  const [code, setCode] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  return <section className="panel span-7"><h1>Recover room ownership</h1><p>Use your saved one-time ownership code, then restore the separate encryption key backup on the room page. Recovery removes management access from the previous browser.</p>
    <form onSubmit={event => { event.preventDefault(); setBusy(true); setError(''); void api<{roomId: string}>('/rooms/recover', 'POST', { recoveryCode: code.trim() })
      .then(result => window.location.assign(`/rooms/${result.roomId}`)).catch(cause => { setError(cause.message); setBusy(false); }); }}>
      <label>Ownership recovery code<input required autoComplete="off" value={code} onChange={event => setCode(event.target.value)} /></label>
      <button disabled={busy}>Recover ownership</button>
    </form>{error && <p role="alert">{error}</p>}
  </section>;
}
