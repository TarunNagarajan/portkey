import { useEffect, useState } from 'react';
import type { Room, RoomInput } from '../shared/rooms.js';
import { api } from './api.js';
import { RoomForm } from './RoomForm.js';

export function Home() {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    api<Room[]>('/rooms').then(data => { if (active) setRooms(data); })
      .catch(error => { if (active) setError(error.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  async function create(input: RoomInput) {
    const room = await api<Room>('/rooms', 'POST', input);
    window.location.assign(`/rooms/${room.id}`);
  }

  return <>
    <header className="page-heading"><p className="eyebrow">WORKSHOP ROOMS</p><h1>A room for the event.</h1>
      <p>Create the room, invite participants, and decide who can enter.</p></header>
    <div className="home-layout">
      <section><h2>Your rooms</h2>
        {error && <p role="alert" className="error">{error}</p>}
        {loading ? <p role="status">Loading rooms…</p> : rooms.length === 0 ? <p className="muted">Your rooms will appear here. Create one to get started.</p> :
          <ul className="room-list">{rooms.map(room => <li key={room.id}>
            <a href={room.role === 'owner' || room.membershipStatus === 'approved' ? `/rooms/${room.id}` : `/join/${room.joinCode}`}>
              <strong>{room.title}</strong><span className={`status ${room.status}`}>{room.status}</span>
              <span className="muted">{room.role === 'owner' ? 'Organizer' : room.membershipStatus} · Ends {new Date(room.expiresAt).toLocaleString()}</span>
            </a></li>)}</ul>}
      </section>
      <section className="create-room"><h2>Create a room</h2><RoomForm submitLabel="Create draft" onSubmit={create} /></section>
    </div>
    <p className="session-note">Access belongs to this browser’s session. Clearing cookies or switching browsers loses it. Keep this organizer browser available for your event.</p>
  </>;
}
