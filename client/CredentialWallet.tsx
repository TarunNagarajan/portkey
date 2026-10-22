import { useEffect, useState } from 'react';
import {
  forgetDamagedGroupCredential,
  forgetGroupCredential,
  loadGroupCredentialState,
  type GroupCredential,
} from './groupCredentialStore.js';

interface DamagedCredential {
  groupId: string;
  error: string;
}

export function CredentialWallet() {
  const [credentials, setCredentials] = useState<GroupCredential[]>([]);
  const [damaged, setDamaged] = useState<DamagedCredential[]>([]);
  const [error, setError] = useState('');
  const [ready, setReady] = useState(false);

  async function refresh() {
    try {
      const state = await loadGroupCredentialState();
      setCredentials(state.credentials);
      setDamaged(state.damaged);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to read local credentials.');
    } finally {
      setReady(true);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function forget(item: GroupCredential) {
    const name = item.name || 'this credential';
    const message = `Forget “${name}” from this browser? This cannot be undone. It does not revoke group membership or room access already granted, but this browser will no longer be able to use this credential.`;
    if (!window.confirm(message)) return;
    try {
      await forgetGroupCredential(item.groupId);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to forget this credential.');
    }
  }

  async function resetDamaged(item: DamagedCredential) {
    if (!window.confirm('Reset only this damaged credential? It cannot be recovered. Other credentials remain untouched.')) return;
    try {
      await forgetDamagedGroupCredential(item.groupId);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to reset this credential.');
    }
  }

  const confirmed = credentials.filter(item => !item.pending);
  const pending = credentials.filter(item => item.pending);

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">THIS BROWSER</p>
          <h1>My credentials</h1>
          <p>Credentials are saved on this browser and can qualify for any room using their group.</p>
        </div>
      </header>
      {error && <p role="alert" className="error">{error}</p>}
      {!ready && <p role="status">Checking local credentials…</p>}
      {ready && !error && credentials.length === 0 && damaged.length === 0 && (
        <section className="panel credential-panel">
          <h2>No saved credentials</h2>
          <p>Open an enrollment link from an organizer to add one. A room link alone cannot create a credential.</p>
        </section>
      )}
      {pending.map(item => (
        <section className="panel credential-panel" key={item.groupId}>
          <h2>Enrollment not confirmed</h2>
          <p>
            This browser has kept a credential after an uncertain enrollment response. Reopen the same
            enrollment link here to retry. It will appear as an enrolled group after the server confirms.
          </p>
          <button type="button" className="secondary" onClick={() => void forget(item)}>
            Forget this credential
          </button>
        </section>
      ))}
      {confirmed.map(item => (
        <section className="panel credential-panel" key={item.groupId}>
          <h2>{item.name}</h2>
          <p>{item.description}</p>
          <p className="muted">This credential is saved in this browser. Clearing site data loses it; there is no recovery or transfer.</p>
          <button type="button" className="secondary" onClick={() => void forget(item)}>
            Forget this credential
          </button>
        </section>
      ))}
      {damaged.map(item => (
        <section className="panel credential-panel" key={item.groupId}>
          <h2>Damaged credential</h2>
          <p>{item.error}</p>
          <p className="muted">This reset deletes only this selected group credential from this browser. It does not change the organizer’s roster or other saved credentials.</p>
          <button type="button" className="secondary" onClick={() => void resetDamaged(item)}>
            Reset this credential
          </button>
        </section>
      ))}
    </>
  );
}
