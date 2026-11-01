import { useCallback, useEffect, useState } from 'react';
import type { Member, Room, RoomInput } from '../shared/rooms.js';
import { ApiError, api, requestFix } from './api.js';
import { RoomArea } from './RoomArea.js';
import { RoomCredential } from './RoomCredential.js';
import { RoomForm } from './RoomForm.js';
import { ShareRoom } from './ShareRoom.js';
import { ActivityLog } from './ActivityLog.js';
import { OwnerRecovery } from './Recovery.js';
import { RoomFiles } from './RoomFiles.js';
import { Icon, Lifetime, StatusBadge, formatDate, formatDistance } from './ui.js';

export function RoomPage({ id }: { id: string }) {
  const [room, setRoom] = useState<Room | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);
  const [roomAccess, setRoomAccess] = useState<string | null>(null);
  const [ownerFingerprint, setOwnerFingerprint] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const current = await api<Room>(`/rooms/${id}`);
      setRoom(current);
      if (current.role === 'owner') setMembers(await api<Member[]>(`/rooms/${id}/members`));
      setError('');
    } catch (error) {
      // A stale location reading is refreshed on demand instead of on every poll.
      if (error instanceof ApiError && error.code === 'GEO_STALE') {
        try {
          await api(`/rooms/${id}/position`, 'POST', await requestFix());
          const current = await api<Room>(`/rooms/${id}`);
          setRoom(current);
          setError('');
          return;
        } catch (retry) {
          setError(retry instanceof Error ? retry.message : 'Unable to load room.');
          return;
        }
      }
      throw error;
    }
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
      <div className="room-intro span-7">
        <a href="/" className="back-link">
          <Icon name="arrow" />
          Back to rooms
        </a>
        <header className="room-head">
          <p className="room-key">
            <Icon name="key" />
            Invitation {room.joinCode}
          </p>
          <h1>{room.title}</h1>
          <p className="room-lede">{room.description || 'No description added.'}</p>
          <p className="room-meta">
            <StatusBadge status={room.status} />
            <span>{owner ? 'You organize this room' : 'Participant view'}</span>
            <span>
              Access ends <strong>{formatDate(room.expiresAt)}</strong>
            </span>
          </p>
          <Lifetime from={room.createdAt} to={room.expiresAt} />
        </header>
        {owner && (
          <div className="actions">
            {room.status === 'draft' && (
              <button disabled={busy} onClick={() => void act(() => api(`/rooms/${id}/open`, 'POST'))}>
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
        )}
      </div>

      <figure className="media tall span-4 start-9">
        <img
          src="/photos/igreja-do-curral-das-freiras-azulejo-tiles.jpg"
          alt="Blue and white patterned tiles lining a church wall above dark wooden pews"
          width="1920"
          height="2560"
          loading="lazy"
        />
        <figcaption>
          <strong>Tiles, older than the room</strong>
          <span>Celsoazevedo</span>
        </figcaption>
      </figure>

      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {editing && (
        <section className="panel edit-panel span-12">
          <h2>Edit room details</h2>
          <RoomForm
            isCreate={false}
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

      <div className="room-body span-12">
        <div className="room-col">
          {owner && room.status === 'open' && (
            roomAccess ? <ShareRoom code={room.joinCode} fingerprint={ownerFingerprint} roomAccess={roomAccess} /> : <p role="status">Preparing the room invitation…</p>
          )}
          {owner && <RoomFiles room={room} onOwnerFingerprint={setOwnerFingerprint} onRoomAccess={setRoomAccess} />}
          {!owner && !error && (
            <>
              <section className="panel participant-welcome">
                <h2>You’re in.</h2>
                <p>
                  {room.credential
                    ? 'Your credential proof admitted this browser. The organizer can still remove access.'
                    : 'Your organizer-approved access is active for this browser.'}
                </p>
              </section>
              {!room.geo && (
                <p className="muted">
                  Files published to this room are encrypted here, in this browser, and removed from
                  the server after the deadline.
                </p>
              )}
              <RoomFiles room={room} />
            </>
          )}
          {owner && <ActivityLog roomId={id} />}
        </div>
        <div className="room-col">
          {owner && (
            <RoomCredential
              room={room}
              hasAdmitted={members.some((member) => ['approved', 'revoked'].includes(member.status))}
              onChanged={reload}
              onError={setError}
            />
          )}
          {owner && (
            <RoomArea
              room={room}
              hasAdmitted={members.some((member) => ['approved', 'revoked'].includes(member.status))}
              onChanged={reload}
              onError={setError}
            />
          )}
          {!owner && room.geo && (
            <p className="area-summary">
              <Icon name="shield" />
              Restricted to {formatDistance(room.geo.radiusM)} around{' '}
              {room.geoLabel ?? 'the organizer’s area'}. Your device must be inside the area to
              enter.
            </p>
          )}
          {owner && room.status === 'draft' && (
            <div className="notice">
              <Icon name="rooms" />
              <p>Open the room when you are ready to receive join requests.</p>
            </div>
          )}
          {owner && !active && (
            <div className="notice">
              <Icon name="shield" />
              <p>This room has closed. New admission is disabled.</p>
            </div>
          )}
        </div>
      </div>

      {owner && <div className="span-12"><OwnerRecovery roomId={id} /></div>}
      {owner && (
        <section className="panel members span-12" data-ui>
          <div className="panel-heading">
            <div>
              <h2>Participant access</h2>
              <p>{room.credential ? 'Participants must prove eligibility; you can decline requests or remove access.' : 'Match the participant’s label before approving.'}</p>
            </div>
            <span className="count-label">
              {members.filter((member) => member.status === 'pending').length} pending ·{' '}
              {members.filter((member) => member.status === 'approved').length} approved
            </span>
          </div>
          {members.length === 0 ? (
            <div className="empty-state">
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
                    <th>Nearby</th>
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
                          {member.credentialVerified && (
                            <span
                              className="credential-flag"
                              title="Admitted by a zero-knowledge credential proof"
                            >
                              proved
                            </span>
                          )}
                        </span>
                      </td>
                      <td>
                        {new Date(member.requestedAt).toLocaleTimeString(undefined, {
                          hour: 'numeric',
                          minute: '2-digit',
                        })}
                      </td>
                      <td>
                        {member.inside == null
                          ? '—'
                          : member.inside
                            ? `Inside${member.distanceM != null ? ` · ${Math.round(member.distanceM)} m` : ''}`
                            : `Outside${member.distanceM != null ? ` · ${Math.round(member.distanceM)} m` : ''}`}
                      </td>
                      <td>
                        <StatusBadge status={member.status} />
                      </td>
                      <td>
                        {room.status === 'open' &&
                          (member.status === 'pending' ? (
                            <div className="actions">
                              <button
                                disabled={busy || (Boolean(room.credential) && !member.credentialVerified)}
                                title={room.credential && !member.credentialVerified ? 'This participant must prove eligibility first.' : undefined}
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
      )}
    </>
  );
}
