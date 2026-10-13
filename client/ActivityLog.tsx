import { useEffect, useState } from 'react';
import type { ActivityKind, ActivityPage, RoomField } from '../shared/activity.js';
import { api } from './api.js';
import { Icon } from './ui.js';

const descriptions: Record<ActivityKind, string> = {
  room_created: 'Room created',
  room_duplicated: 'Room created from a template',
  room_updated: 'Room details updated',
  room_opened: 'Room opened',
  room_closed: 'Room closed',
  join_requested: 'Access requested',
  member_approved: 'Access approved',
  member_denied: 'Access declined',
  member_revoked: 'Access removed',
};

const fields: Record<RoomField, string> = {
  title: 'Title',
  description: 'Description',
  expiresAt: 'Access deadline',
};

export function ActivityLog({ roomId }: { roomId: string }) {
  const [page, setPage] = useState<ActivityPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    setLoading(true);
    async function load() {
      try {
        const suffix = cursor ? `?before=${encodeURIComponent(cursor)}` : '';
        const result = await api<ActivityPage>(`/rooms/${roomId}/activity${suffix}`);
        if (active) {
          setPage(result);
          setError('');
        }
      } catch (error) {
        if (active) setError(error instanceof Error ? error.message : 'Unable to load activity.');
      } finally {
        if (active) setLoading(false);
      }
      if (active && !cursor) timer = setTimeout(() => void load(), 5000);
    }
    void load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [roomId, cursor, attempt]);

  return (
    <section className="panel activity-panel" aria-labelledby="activity-title">
      <div className="panel-heading">
        <div>
          <h2 id="activity-title">Room activity</h2>
          <p>
            {cursor
              ? 'Earlier room and admission changes.'
              : 'Recent room and admission changes. Newest first.'}
          </p>
        </div>
        {cursor && (
          <button className="secondary" disabled={loading} onClick={() => setCursor(null)}>
            Back to latest
          </button>
        )}
      </div>
      {error && (
        <div className="activity-error">
          <p role="alert" className="error">
            {error}
          </p>
          <button className="secondary" onClick={() => setAttempt((value) => value + 1)}>
            Retry activity
          </button>
        </div>
      )}
      {loading && !page ? (
        <p className="empty-state" role="status">
          Loading activity…
        </p>
      ) : page?.events.length === 0 ? (
        <div className="empty-state">
          <h3>No recorded activity yet</h3>
          <p>Changes made after activity logging was enabled will appear here.</p>
        </div>
      ) : (
        <ol className="activity-list">
          {page?.events.map((event) => (
            <li key={event.id}>
              <span className="activity-symbol">
                <Icon
                  name={
                    event.kind.startsWith('member_') || event.kind === 'join_requested'
                      ? 'shield'
                      : 'clock'
                  }
                />
              </span>
              <div className="activity-description">
                <strong>{descriptions[event.kind]}</strong>
                {event.memberLabel && <p>{event.memberLabel}</p>}
                {event.changedFields.length > 0 && (
                  <p>{event.changedFields.map((field) => fields[field]).join(' · ')}</p>
                )}
              </div>
              <time dateTime={event.createdAt} title={new Date(event.createdAt).toLocaleString()}>
                {new Date(event.createdAt).toLocaleString(undefined, {
                  month: 'short',
                  day: 'numeric',
                  hour: 'numeric',
                  minute: '2-digit',
                })}
              </time>
            </li>
          ))}
        </ol>
      )}
      {page && (
        <div className="activity-pagination">
          <span>{cursor ? 'Historical page' : 'Updates automatically'}</span>
          {page.nextCursor && (
            <button
              className="secondary"
              disabled={loading || !!error}
              onClick={() => setCursor(page.nextCursor)}
            >
              {loading ? 'Loading…' : 'Older activity'}
            </button>
          )}
        </div>
      )}
    </section>
  );
}
