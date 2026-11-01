import { useState } from 'react';
import type { Room } from '../shared/rooms.js';
import {
  departments,
  departmentLabel,
  MAX_CREDENTIAL_YEAR,
  MIN_CREDENTIAL_YEAR,
} from '../shared/credentials.js';
import { api } from './api.js';
import { Icon } from './ui.js';

export function RoomCredential({
  room,
  hasAdmitted,
  onChanged,
  onError,
}: {
  room: Room;
  hasAdmitted: boolean;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const active = room.status === 'draft' || room.status === 'open';
  const editable = active && !hasAdmitted;
  const [open, setOpen] = useState(false);
  const [dept, setDept] = useState(room.credential?.dept ?? departments[0].code);
  const [year, setYear] = useState(room.credential?.year ?? new Date().getFullYear() + 4);
  const [busy, setBusy] = useState(false);

  async function apply() {
    setBusy(true);
    try {
      await api(`/rooms/${room.id}/credential`, 'PUT', { dept: Number(dept), year: Number(year) });
      setOpen(false);
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unable to set the credential gate.');
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api(`/rooms/${room.id}/credential`, 'DELETE');
      setOpen(false);
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unable to remove the credential gate.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel credential-panel" data-ui>
      <div className="panel-heading">
        <div>
          <h2>Credential gate</h2>
          <p>
            A valid zero-knowledge proof of a university credential admits a participant without
            collecting a name, roll number, or email.
          </p>
        </div>
      </div>
      {room.credential ? (
        <p className="area-summary">
          <Icon name="shield" />
          Admits <strong>{departmentLabel(room.credential.dept)}</strong>, class of{' '}
          <strong>{room.credential.year}</strong>.
        </p>
      ) : (
        <p className="muted">
          No credential gate. Join requests wait for your approval, and participants may use any
          label.
        </p>
      )}
      {editable && !open && (
        <div className="actions">
          <button className="secondary" disabled={busy} onClick={() => setOpen(true)}>
            {room.credential ? 'Change requirement' : 'Require a credential'}
          </button>
          {room.credential && (
            <button className="secondary" disabled={busy} onClick={() => void remove()}>
              Remove gate
            </button>
          )}
        </div>
      )}
      {active && hasAdmitted && (
        <p className="muted">The gate is fixed once a participant has been admitted.</p>
      )}
      {editable && open && (
        <div className="credential-editor">
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
          <div className="actions">
            <button disabled={busy} onClick={() => void apply()}>
              {busy ? 'Saving…' : 'Apply gate'}
            </button>
            <button className="secondary" disabled={busy} onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
          <p className="muted">
            One credential holds one seat: the proof carries a per-room nullifier, so the same
            credential cannot join twice, and it cannot be linked across rooms.
          </p>
        </div>
      )}
    </section>
  );
}
