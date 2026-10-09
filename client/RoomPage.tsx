import { useCallback, useEffect, useState } from 'react';
import type { Member, Room, RoomInput } from '../shared/rooms.js';
import { api } from './api.js';
import { RoomForm } from './RoomForm.js';
import { ShareRoom } from './ShareRoom.js';

export function RoomPage({ id }: { id: string }) {
  const [room, setRoom] = useState<Room | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);

  const reload = useCallback(async () => {
    const current = await api<Room>(`/rooms/${id}`);
    setRoom(current);
    if (current.role === 'owner') setMembers(await api<Member[]>(`/rooms/${id}/members`));
    setError('');
  }, [id]);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try { if (active) await reload(); }
      catch (error) { if (active) setError(error instanceof Error ? error.message : 'Unable to load room.'); }
      if (active) timer = setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [reload]);

  async function act(work: () => Promise<unknown>) {
    setBusy(true);
    try { await work(); await reload(); }
    catch (error) { setError(error instanceof Error ? error.message : 'Unable to update room.'); }
    finally { setBusy(false); }
  }

  async function save(input: RoomInput) {
    await api(`/rooms/${id}`, 'PATCH', input);
    setEditing(false);
    await reload();
  }

  if (!room) return <p role={error ? 'alert' : 'status'}>{error || 'Loading room…'}</p>;
  const owner = room.role === 'owner';
  const active = ['draft', 'open'].includes(room.status);

  return <>
    <header className="page-heading"><p className="eyebrow">{owner ? 'ORGANIZER' : 'PARTICIPANT'} · <span className={`status ${room.status}`}>{room.status}</span></p>
      <h1>{room.title}</h1><p>{room.description || 'No description added.'}</p>
      <p className="muted">Access ends {new Date(room.expiresAt).toLocaleString()}</p></header>
    {error && <p role="alert" className="error">{error}</p>}
    {owner && <>
      <div className="actions">
        {room.status === 'draft' && <button disabled={busy} onClick={() => void act(() => api(`/rooms/${id}/open`, 'POST'))}>Open room</button>}
        {active && <button className="secondary" disabled={busy} onClick={() => setEditing(!editing)}>{editing ? 'Cancel editing' : 'Edit details'}</button>}
        {active && <button className="danger" disabled={busy} onClick={() => {
          if (window.confirm('Close this room? Participants will lose access and the room cannot reopen.')) void act(() => api(`/rooms/${id}/close`, 'POST'));
        }}>Close room</button>}
      </div>
      {editing && <RoomForm initial={{ title: room.title, description: room.description, expiresAt: room.expiresAt }} submitLabel="Save details" onSubmit={save} />}
      {room.status === 'open' && <ShareRoom code={room.joinCode} />}
      {room.status === 'draft' && <p className="muted">Open the room when you are ready to receive join requests.</p>}
      {!active && <p>This room has closed. New admission is disabled.</p>}
      <section className="members"><h2>Participant access</h2><p className="muted">Labels are chosen by participants. Match the label with the person before approving.</p>
        {members.length === 0 ? <p>No join requests yet.</p> : <div className="table-scroll"><table><thead><tr><th>Label</th><th>Requested</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>{members.map(member => <tr key={member.id}><td>{member.label}</td><td>{new Date(member.requestedAt).toLocaleTimeString()}</td><td>{member.status}</td>
            <td>{room.status === 'open' && (member.status === 'pending' ? <div className="actions">
              <button disabled={busy} onClick={() => void act(() => api(`/rooms/${id}/members/${member.id}`, 'PATCH', { status: 'approved' }))}>Approve</button>
              <button disabled={busy} className="secondary" onClick={() => void act(() => api(`/rooms/${id}/members/${member.id}`, 'PATCH', { status: 'denied' }))}>Decline</button>
            </div> : member.status === 'approved' ? <button disabled={busy} className="secondary" onClick={() => void act(() => api(`/rooms/${id}/members/${member.id}`, 'PATCH', { status: 'revoked' }))}>Remove access</button> : '—')}</td>
          </tr>)}</tbody></table></div>}
      </section>
    </>}
    {!owner && !error && <p>You have organizer-approved access to this room. File sharing will be added in the next module.</p>}
  </>;
}
