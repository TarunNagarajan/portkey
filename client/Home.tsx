import { useEffect, useState } from 'react';
import type { Room, RoomCreateInput } from '../shared/rooms.js';
import { api } from './api.js';
import { RoomForm } from './RoomForm.js';
import { Icon, Lifetime, StatusBadge } from './ui.js';

/* Every room is one line: its name, its invitation, and the window it has left. */
function RoomRow({ room }: { room: Room }) {
  const open =
    room.role === 'owner' || room.membershipStatus === 'approved'
      ? `/rooms/${room.id}`
      : `/join/${room.joinCode}`;
  return (
    <li>
      <div className="rooms-main">
        <a className="room-title" href={open}>
          {room.title}
        </a>
        <p className="rooms-meta">
          <code>{room.joinCode}</code>
          <span>
            {room.role === 'owner' ? 'You organize this room' : `Access ${room.membershipStatus}`}
          </span>
        </p>
        <Lifetime from={room.createdAt} to={room.expiresAt} />
      </div>
      <div className="rooms-aside">
        <StatusBadge status={room.status} />
        {room.role === 'owner' && (
          <a
            className="text-link"
            aria-label={`Use ${room.title} as a template`}
            href={`/?template=${room.id}#new-room`}
          >
            <Icon name="copy" />
            Template
          </a>
        )}
      </div>
    </li>
  );
}

export function Home() {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [template, setTemplate] = useState<Room | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const templateId = new URLSearchParams(window.location.search).get('template');

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

  async function create(input: RoomCreateInput) {
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

  return (
    <>
      <section className="hero span-5" aria-labelledby="home-title">
        <h1 id="home-title" className="headline-reveal">
          Your rooms
        </h1>
        <p className="lede">
          A room opens with an invitation and no account. Seven days is the longest it can last.
        </p>
        <div className="hero-actions">
          <a className="button" href="#new-room">
            <Icon name="plus" />
            New room
          </a>
          {rooms.length > 0 && (
            <a className="text-link" href="#rooms">
              See the rooms
              <Icon name="arrow" />
            </a>
          )}
        </div>
      </section>

      <section
        className="panel rooms span-6 start-7"
        id="rooms"
        data-ui
        aria-labelledby="directory-title"
      >
        <div className="rooms-head">
          <h2 id="directory-title">Rooms in this browser</h2>
          <span className="count-label">
            {loading ? 'Reading…' : `${filtered.length} of ${rooms.length}`}
          </span>
        </div>
        <div className="rooms-tools">
          <label className="search-field">
            <span className="sr-only">Search rooms</span>
            <Icon name="search" />
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search rooms"
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
        {loading && (
          <p className="muted" role="status">
            Reading this browser’s rooms…
          </p>
        )}
        {!loading && rooms.length === 0 && (
          <div className="empty-state">
            <h3>Your first room starts here</h3>
            <p>
              Create a draft, then share its invitation. Each browser asks for access, and you
              approve it by name.
            </p>
          </div>
        )}
        {!loading && rooms.length > 0 && filtered.length === 0 && (
          <div className="empty-state">
            <h3>No matching rooms</h3>
            <p>Try another word, or show every status.</p>
            <button
              className="text-button"
              onClick={() => {
                setSearch('');
                setStatus('all');
              }}
            >
              Clear the filters
            </button>
          </div>
        )}
        {filtered.length > 0 && (
          <ul className="rooms-list">
            {filtered.map((room) => (
              <RoomRow key={room.id} room={room} />
            ))}
          </ul>
        )}
      </section>

      <figure className="media span-4">
        <div className="crossfade">
          <img
            src="/photos/set-old-keys-hanging-wall.webp"
            alt="Bunches of old iron keys hanging on a dark wooden wall"
            width="1024"
            height="683"
          />
          <img
            src="/photos/entrance-to-the-east-block-of-the.jpg"
            alt="A stone doorway of studded wooden doors under a carved arch"
            width="1920"
            height="2880"
            loading="lazy"
          />
          <img
            src="/photos/igreja-do-curral-das-freiras-azulejo-tiles.jpg"
            alt="Blue and white patterned tiles lining a church wall above dark wooden pews"
            width="1920"
            height="2560"
            loading="lazy"
          />
        </div>
        <figcaption>
          <strong>One key per room</strong>
          <span>Markus Spiske</span>
        </figcaption>
      </figure>

      <section
        className="panel create-room span-7 start-6"
        id="new-room"
        data-ui
        aria-labelledby="create-title"
      >
        <div className="panel-heading">
          <div>
            <h2 id="create-title">{template ? 'Reuse a room' : 'Create a room'}</h2>
            <p>
              {template
                ? 'A fresh draft with a new invitation. Participants and approvals stay behind.'
                : 'Set the title and the deadline now. Open it when you are ready to receive requests.'}
            </p>
          </div>
        </div>
        {template && (
          <div className="template-notice">
            <Icon name="copy" />
            <div>
              <strong>{template.title}</strong>
              <p>Participants and approvals are not copied.</p>
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
                    credential: template.credential
                      ? { dept: template.credential.dept, year: template.credential.year }
                      : null,
                  }
                : undefined
            }
            submitLabel="Create draft"
            onSubmit={create}
          />
        )}
      </section>

      <section className="note span-12">
        <h2>What stays where</h2>
        <ul>
          <li>
            <Icon name="key" />
            <span>
              Keys are made in this browser. The server never holds a room’s files or notes in the
              clear, and it cannot read what it stores for you.
            </span>
          </li>
          <li>
            <Icon name="rooms" />
            <span>
              Files are encrypted before they upload, and the server drops them the moment the
              deadline passes.
            </span>
          </li>
          <li>
            <Icon name="clock" />
            <span>
              A room cannot outlive its deadline, and its invitation only opens while the room
              itself is open.
            </span>
          </li>
        </ul>
      </section>

      <figure className="media band span-8">
        <img
          src="/photos/entrance-to-the-east-block-of-the.jpg"
          alt="A stone doorway of studded wooden doors under a carved arch"
          width="1920"
          height="2880"
          loading="lazy"
        />
        <figcaption>
          <strong>One door per room</strong>
          <span>Hayden Soloviev</span>
        </figcaption>
      </figure>

      <figure className="media lock-clip span-4 start-9">
        <video
          autoPlay
          muted
          loop
          playsInline
          preload="metadata"
          poster="/photos/einsteckschloss-animation-poster.jpg"
          width="480"
          height="480"
          aria-hidden="true"
        >
          <source src="/photos/einsteckschloss-animation.webm" type="video/webm" />
        </video>
        <figcaption>
          <strong>The lock, open</strong>
          <span>Andreas Gortan</span>
        </figcaption>
      </figure>

      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </>
  );
}
