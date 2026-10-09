import { useEffect, useState, type FormEvent } from 'react';
import type { PublicRoom } from '../shared/rooms.js';
import { api } from './api.js';

export function JoinPage({ code }: { code: string }) {
  const [room, setRoom] = useState<PublicRoom | null>(null);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const value = await api<PublicRoom>(`/join/${code}`);
        if (active) { setRoom(value); setError(''); }
      } catch (error) { if (active) setError(error instanceof Error ? error.message : 'Unable to load room.'); }
      if (active) timer = setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [code]);

  async function join(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api(`/join/${code}`, 'POST', { label });
      setRoom(await api<PublicRoom>(`/join/${code}`));
      setError('');
    } catch (error) { setError(error instanceof Error ? error.message : 'Unable to request access.'); }
    finally { setBusy(false); }
  }

  if (!room) return <p role={error ? 'alert' : 'status'}>{error || 'Finding room…'}</p>;
  return <section className="join-page">
    <p className="eyebrow">JOIN A WORKSHOP · {room.status}</p><h1>{room.title}</h1>
    <p>{room.description}</p><p className="muted">Access ends {new Date(room.expiresAt).toLocaleString()}</p>
    {error && <p role="alert" className="error">{error}</p>}
    {room.status !== 'open' ? <p>{room.status === 'draft' ? 'The organizer has not opened this room yet.' : 'This room has closed.'}</p> :
      room.isOwner || room.membershipStatus === 'approved' ? <a className="button" href={`/rooms/${room.id}`}>Enter room</a> :
      room.membershipStatus === 'pending' ? <p role="status">Waiting for organizer approval. This page updates automatically.</p> :
      room.membershipStatus === 'revoked' || room.membershipStatus === 'denied' ? <p>The organizer has declined access for this browser.</p> :
      <form onSubmit={join}><label>Your label<input required maxLength={50} value={label} onChange={event => setLabel(event.target.value)} placeholder="A nickname or team label" /></label>
        <p className="muted">Use a label the organizer can recognize. No email, roll number, or external ID is required.</p>
        <button disabled={busy}>{busy ? 'Requesting…' : 'Request access'}</button></form>}
  </section>;
}
