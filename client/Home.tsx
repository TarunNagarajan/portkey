import { useEffect, useState } from 'react';
import type { Room, RoomInput } from '../shared/rooms.js';
import { api, getPublicOrigin, isLocalOrigin } from './api.js';
import { RoomForm } from './RoomForm.js';
import { Icon, StatusBadge, formatDate } from './ui.js';

export function Home() {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [template, setTemplate] = useState<Room | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const templateId = new URLSearchParams(window.location.search).get('template');
  const localOnly = isLocalOrigin(getPublicOrigin());

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await api<Room[]>('/rooms');
        if (active) setRooms(data);
        if (templateId) {
          const original = await api<Room>(`/rooms/${templateId}`);
          if (original.role !== 'owner')
            throw new Error('Only your own rooms can be used as templates.');
          if (active) setTemplate(original);
        }
      } catch (error) {
        if (active) setError(error instanceof Error ? error.message : 'Unable to load rooms.');
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, [templateId]);

  async function create(input: RoomInput) {
    const path = template ? `/rooms/${template.id}/duplicate` : '/rooms';
    const room = await api<Room>(path, 'POST', input);
    window.location.assign(`/rooms/${room.id}`);
  }

  const filtered = rooms.filter(
    (room) =>
      (status === 'all' || room.status === status) &&
      `${room.title} ${room.description}`
        .toLocaleLowerCase()
        .includes(search.trim().toLocaleLowerCase()),
  );
  const counts = [
    ['Total rooms', rooms.length],
    ['Open now', rooms.filter((room) => room.status === 'open').length],
    ['Drafts', rooms.filter((room) => room.status === 'draft').length],
    [
      'Closed / expired',
      rooms.filter((room) => ['closed', 'expired'].includes(room.status)).length,
    ],
  ];

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">YOUR WORKSPACE</p>
          <h1>Your rooms</h1>
          <p>Manage your workshop rooms and participant access.</p>
        </div>
        <a className="button" href="#new-room">
          <Icon name="plus" />
          New room
        </a>
      </header>
      <dl className="workspace-stats">
        {counts.map(([label, count]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{loading ? '—' : count}</dd>
          </div>
        ))}
      </dl>
      {localOnly && <p className="muted">This local address is for this computer. Phone sharing needs a public HTTPS address.</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="home-layout">
        <section className="panel room-directory" aria-labelledby="directory-title">
          <div className="panel-heading">
            <div>
              <h2 id="directory-title">Room directory</h2>
              <p>Manage your events and revisit your invitations.</p>
            </div>
            <span className="count-label">{filtered.length} rooms</span>
          </div>
          <div className="directory-toolbar">
            <label className="search-field">
              <span className="sr-only">Search rooms</span>
              <Icon name="search" />
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search by title or description"
              />
            </label>
            <label>
              <span className="sr-only">Filter rooms by status</span>
              <select value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="all">All statuses</option>
                <option value="draft">Draft</option>
                <option value="open">Open</option>
                <option value="closed">Closed</option>
                <option value="expired">Expired</option>
              </select>
            </label>
          </div>
          {loading ? (
            <p className="empty-state" role="status">
              Loading rooms…
            </p>
          ) : filtered.length === 0 ? (
            <div className="empty-state">
              <span className="empty-symbol">
                <Icon name={rooms.length ? 'search' : 'rooms'} />
              </span>
              <h3>{rooms.length ? 'No matching rooms' : 'Your first room starts here'}</h3>
              <p>
                {rooms.length
                  ? 'Try a different search or status.'
                  : 'Create a draft, open it when you’re ready, and invite your participants.'}
              </p>
              {rooms.length > 0 && (
                <button
                  className="text-button"
                  onClick={() => {
                    setSearch('');
                    setStatus('all');
                  }}
                >
                  Clear filters
                </button>
              )}
            </div>
          ) : (
            <ul className="room-list">
              {filtered.map((room) => (
                <li key={room.id}>
                  <div className="room-list-main">
                    <span className="room-symbol">
                      <Icon name="rooms" />
                    </span>
                    <div className="room-list-details">
                      <a
                        className="room-title"
                        href={
                          room.role === 'owner' || room.membershipStatus === 'approved'
                            ? `/rooms/${room.id}`
                            : `/join/${room.joinCode}`
                        }
                      >
                        {room.title}
                      </a>
                      <p>
                        {room.role === 'owner' ? 'Organizer' : room.membershipStatus} <span>·</span>{' '}
                        Ends {formatDate(room.expiresAt)}
                      </p>
                    </div>
                    <StatusBadge status={room.status} />
                  </div>
                  {room.role === 'owner' && (
                    <a
                      className="template-link"
                      aria-label={`Use ${room.title} as template`}
                      href={`/?template=${room.id}#new-room`}
                    >
                      <Icon name="copy" />
                      Use as template
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
          <div className="panel-footnote">
            Showing {filtered.length} of {rooms.length} rooms in this browser.
          </div>
        </section>
        <section className="panel create-room" id="new-room" aria-labelledby="create-title">
          <div className="panel-heading">
            <div>
              <h2 id="create-title">{template ? 'Reuse a room' : 'Create a room'}</h2>
              <p>
                {template
                  ? 'A fresh draft with a new invitation.'
                  : 'Set the details now. Open it when ready.'}
              </p>
            </div>
          </div>
          {template && (
            <div className="template-notice">
              <Icon name="copy" />
              <div>
                <strong>{template.title}</strong>
                <p>Participants and approvals won’t be copied.</p>
                <a href="/#new-room">Start from scratch</a>
              </div>
            </div>
          )}
          {!loading && (
            <RoomForm
              key={template?.id ?? 'new'}
              initial={
                template
                  ? {
                      title: template.title,
                      description: template.description,
                      expiresAt: new Date(Date.now() + 86400_000).toISOString(),
                    }
                  : undefined
              }
              submitLabel="Create draft"
              onSubmit={create}
            />
          )}
        </section>
      </div>
    </>
  );
}
