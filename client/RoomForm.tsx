import { useState, type FormEvent } from 'react';
import type { RoomInput } from '../shared/rooms.js';

function localDate(value: Date) {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function RoomForm({
  initial,
  submitLabel,
  onSubmit,
}: {
  initial?: RoomInput;
  submitLabel: string;
  onSubmit: (input: RoomInput) => Promise<void>;
}) {
  const [title, setTitle] = useState(initial?.title ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [expiresAt, setExpiresAt] = useState(
    localDate(initial ? new Date(initial.expiresAt) : new Date(Date.now() + 24 * 60 * 60 * 1000)),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await onSubmit({ title, description, expiresAt: new Date(expiresAt).toISOString() });
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Unable to save the room.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="room-form">
      <label>
        Room title
        <input
          required
          maxLength={100}
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Design workshop"
        />
      </label>
      <label>
        Public description
        <textarea
          maxLength={500}
          rows={3}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          placeholder="What participants should know before joining"
        />
      </label>
      <label>
        Access ends
        <input
          type="datetime-local"
          required
          value={expiresAt}
          onChange={(event) => setExpiresAt(event.target.value)}
        />
      </label>
      <p className="muted">
        Times use your device’s local time zone. Rooms can stay available for up to seven days.
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button disabled={busy}>{busy ? 'Saving…' : submitLabel}</button>
    </form>
  );
}
