import { useState, type FormEvent } from 'react';
import type { RoomCreateInput } from '../shared/rooms.js';
import {
  departments,
  MAX_CREDENTIAL_YEAR,
  MIN_CREDENTIAL_YEAR,
} from '../shared/credentials.js';

function localDate(value: Date) {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function RoomForm({
  initial,
  submitLabel,
  isCreate = true,
  onSubmit,
}: {
  initial?: RoomCreateInput;
  submitLabel: string;
  isCreate?: boolean;
  onSubmit: (input: RoomCreateInput) => Promise<void>;
}) {
  const [title, setTitle] = useState(initial?.title ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [expiresAt, setExpiresAt] = useState(
    localDate(initial ? new Date(initial.expiresAt) : new Date(Date.now() + 24 * 60 * 60 * 1000)),
  );
  const [gate, setGate] = useState(Boolean(initial?.credential));
  const [dept, setDept] = useState(initial?.credential?.dept ?? departments[0].code);
  const [year, setYear] = useState(initial?.credential?.year ?? new Date().getFullYear() + 4);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const input: RoomCreateInput = {
        title,
        description,
        expiresAt: new Date(expiresAt).toISOString(),
      };
      if (isCreate) input.credential = gate ? { dept: Number(dept), year: Number(year) } : null;
      await onSubmit(input);
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
      {isCreate && (
        <fieldset className="credential-gate">
          <legend>Admission</legend>
          <label className="credential-toggle">
            <input
              type="checkbox"
              checked={gate}
              onChange={(event) => setGate(event.target.checked)}
            />
            Require a university credential proof
          </label>
          {gate && (
            <div className="credential-fields">
              <label>
                Department
                <select value={dept} onChange={(event) => setDept(Number(event.target.value))}>
                  {departments.map((entry) => (
                    <option key={entry.code} value={entry.code}>
                      {entry.label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Class of
                <input
                  type="number"
                  min={MIN_CREDENTIAL_YEAR}
                  max={MAX_CREDENTIAL_YEAR}
                  value={year}
                  onChange={(event) => setYear(Number(event.target.value))}
                />
              </label>
            </div>
          )}
          {gate && (
            <p className="muted">
              A valid proof from the configured institution admits the holder automatically. You
              can still remove their access, and one credential holds one seat per room. Change the
              gate later from the room page.
            </p>
          )}
        </fieldset>
      )}
      <p className="muted">
        Times use your device’s local time zone. Rooms can stay available for up to seven days.
      </p>
      {isCreate && (
        <p className="muted">
          Shared files are removed automatically from the server after this deadline. Room
          history, membership and public keys remain; copies already downloaded and browser
          backups are not erased.
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button disabled={busy}>{busy ? 'Saving…' : submitLabel}</button>
    </form>
  );
}
