import { useCallback, useEffect, useState } from 'react';
import type { Member, Room, RoomInput } from '../shared/rooms.js';
import { api } from './api.js';
import { RoomForm } from './RoomForm.js';
import { ShareRoom } from './ShareRoom.js';
import { ActivityLog } from './ActivityLog.js';
import { PrivateInbox } from './PrivateInbox.js';
import { Icon, StatusBadge, formatDate } from './ui.js';

export function RoomPage({ id }: { id: string }) {
  const [room, setRoom] = useState<Room | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);
  const [inboxFingerprint, setInboxFingerprint] = useState<string | null>(null);

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
      try {
        if (active) await reload();
      } catch (error) {
        if (active) setError(error instanceof Error ? error.message : 'Unable to load room.');
      }
      if (active) timer = setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [reload]);

  async function act(work: () => Promise<unknown>) {
    setBusy(true);
    try {
      await work();
      await reload();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to update room.');
    } finally {
      setBusy(false);
    }
  }

  async function save(input: RoomInput) {
    await api(`/rooms/${id}`, 'PATCH', input);
    setEditing(false);
    await reload();
  }

  if (!room) return <p role={error ? 'alert' : 'status'}>{error || 'Loading room…'}</p>;
  const owner = room.role === 'owner';
  const active = ['draft', 'open'].includes(room.status);

  return (
    <>
      <a href="/" className="back-link">
        ← Back to rooms
      </a>
      <header className="page-heading">
        <div>
          <p className="eyebrow">{owner ? 'ORGANIZER' : 'PARTICIPANT'} VIEW</p>
          <h1>{room.title}</h1>
          <p>{room.description || 'No description added.'}</p>
        </div>
        <StatusBadge status={room.status} />
      </header>
      <div className="room-summary">
        <span>
          <Icon name="clock" />
          Access ends <strong>{formatDate(room.expiresAt)}</strong>
        </span>
        <span>
          <Icon name="shield" />
          Organizer approval required
        </span>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {owner && (
        <>
          <div className="actions">
            {room.status === 'draft' && (
              <button
                disabled={busy}
                onClick={() => void act(() => api(`/rooms/${id}/open`, 'POST'))}
              >
                Open room
              </button>
            )}
            {active && (
              <button className="secondary" disabled={busy} onClick={() => setEditing(!editing)}>
                {editing ? 'Cancel editing' : 'Edit details'}
              </button>
            )}
            <a className="button secondary" href={`/?template=${room.id}#new-room`}>
              <Icon name="copy" />
              Use as template
            </a>
            {active && (
              <button
                className="danger"
                disabled={busy}
                onClick={() => {
                  if (
                    window.confirm(
                      'Close this room? Participants will lose access and the room cannot reopen.',
                    )
                  )
                    void act(() => api(`/rooms/${id}/close`, 'POST'));
                }}
              >
                Close room
              </button>
            )}
          </div>
          {editing && (
            <section className="panel edit-panel">
              <h2>Edit room details</h2>
              <RoomForm
                initial={{
                  title: room.title,
                  description: room.description,
                  expiresAt: room.expiresAt,
                }}
                submitLabel="Save details"
                onSubmit={save}
              />
            </section>
          )}
          {room.status === 'open' && <ShareRoom code={room.joinCode} fingerprint={inboxFingerprint} />}
          <PrivateInbox room={room} onOwnerFingerprint={owner => { if (owner) setInboxFingerprint(owner); }} />
          {room.status === 'draft' && (
            <div className="notice">
              <Icon name="rooms" />
              <p>Open the room when you are ready to receive join requests.</p>
            </div>
          )}
          {!active && (
            <div className="notice">
              <Icon name="shield" />
              <p>This room has closed. New admission is disabled.</p>
            </div>
          )}
          <section className="panel members">
            <div className="panel-heading">
              <div>
                <h2>Participant access</h2>
                <p>Match the participant’s label before approving.</p>
              </div>
              <span className="count-label">
                {members.filter((member) => member.status === 'pending').length} pending ·{' '}
                {members.filter((member) => member.status === 'approved').length} approved
              </span>
            </div>
            {members.length === 0 ? (
              <div className="empty-state">
                <span className="empty-symbol">
                  <Icon name="shield" />
                </span>
                <h3>No requests yet</h3>
                <p>Join requests will appear here after you share the room.</p>
              </div>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Participant</th>
                      <th>Requested</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map((member) => (
                      <tr key={member.id}>
                        <td>
                          <span className="participant-label">
                            <span className="avatar">{member.label.slice(0, 2).toUpperCase()}</span>
                            {member.label}
                          </span>
                        </td>
                        <td>
                          {new Date(member.requestedAt).toLocaleTimeString(undefined, {
                            hour: 'numeric',
                            minute: '2-digit',
                          })}
                        </td>
                        <td>
                          <StatusBadge status={member.status} />
                        </td>
                        <td>
                          {room.status === 'open' &&
                            (member.status === 'pending' ? (
                              <div className="actions">
                                <button
                                  disabled={busy}
                                  onClick={() =>
                                    void act(() =>
                                      api(`/rooms/${id}/members/${member.id}`, 'PATCH', {
                                        status: 'approved',
                                      }),
                                    )
                                  }
                                >
                                  Approve
                                </button>
                                <button
                                  disabled={busy}
                                  className="secondary"
                                  onClick={() =>
                                    void act(() =>
                                      api(`/rooms/${id}/members/${member.id}`, 'PATCH', {
                                        status: 'denied',
                                      }),
                                    )
                                  }
                                >
                                  Decline
                                </button>
                              </div>
                            ) : member.status === 'approved' ? (
                              <button
                                disabled={busy}
                                className="secondary"
                                onClick={() =>
                                  void act(() =>
                                    api(`/rooms/${id}/members/${member.id}`, 'PATCH', {
                                      status: 'revoked',
                                    }),
                                  )
                                }
                              >
                                Remove access
                              </button>
                            ) : (
                              '—'
                            ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <ActivityLog roomId={id} />
        </>
      )}
      {!owner && !error && (
        <>
          <section className="panel participant-welcome">
            <span className="empty-symbol"><Icon name="shield" /></span>
            <h2>You’re in.</h2>
            <p>Your organizer-approved access is active for this browser.</p>
          </section>
          <PrivateInbox room={room} />
        </>
      )}
    </>
  );
}
