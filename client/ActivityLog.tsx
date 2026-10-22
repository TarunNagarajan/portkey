import { useEffect, useState } from 'react';
import type { ActivityKind, ActivityPage, RoomField } from '../shared/activity.js';
import { api, ApiError } from './api.js';
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
  submission_cleanup_enabled: 'Automatic submission cleanup enabled',
  submissions_purged: 'Room submissions removed after deadline',
  admission_passes_issued: 'Admission passes issued',
  pass_revoked: 'Admission pass revoked',
  pass_redeemed: 'Admission pass redeemed',
  proof_enrollments_issued: 'Workshop enrollment links issued',
  proof_enrollment_revoked: 'Workshop enrollment link revoked',
  proof_admitted: 'Workshop proof accepted',
};

const fields: Record<RoomField, string> = {
  title: 'Title',
  description: 'Description',
  expiresAt: 'Access deadline',
  admissionPolicy: 'Admission policy',
};

export function ActivityLog({ roomId }: { roomId: string }) {
  const [result, setResult] = useState<{
    roomId: string;
    cursor: string | null;
    page: ActivityPage;
  } | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const page = result?.roomId === roomId && result.cursor === cursor ? result.page : null;

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setLoading(true);
    setError('');
    async function load() {
      let canPoll = true;
      try {
        const suffix = cursor ? `?before=${encodeURIComponent(cursor)}` : '';
        const page = await api<ActivityPage>(
          `/rooms/${roomId}/activity${suffix}`,
          'GET',
          undefined,
          controller.signal,
        );
        if (active) {
          setResult({ roomId, cursor, page });
          setError('');
        }
      } catch (error) {
        if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
          canPoll = false;
          if (active) setResult(null);
        }
        if (active) setError(error instanceof Error ? error.message : 'Unable to load activity.');
      } finally {
        if (active) setLoading(false);
      }
      if (active && canPoll && !cursor) timer = setTimeout(() => void load(), 5000);
    }
    void load();
    return () => {
      active = false;
      controller.abort();
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
          <button className="secondary" onClick={() => setCursor(null)}>
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
