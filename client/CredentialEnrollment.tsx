import { useEffect, useState } from 'react';
import { ApiError, api } from './api.js';
import { confirmGroupCredential, loadOrCreateGroupCredential } from './groupCredentialStore.js';

interface CredentialDescriptor {
  id: string;
  name: string;
  description: string;
  available: boolean;
  availableUntil: string | null;
}

function enrollmentToken(): { token: string | null; invalid: boolean } {
  const values = new URLSearchParams(window.location.hash.slice(1)).getAll('enroll');
  if (values.length === 0) return { token: null, invalid: false };
  const token = values[0];
  if (values.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    return { token: null, invalid: true };
  }
  try {
    const decoded = atob(token.replaceAll('-', '+').replaceAll('_', '/') + '=');
    const canonical = btoa(decoded).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    return decoded.length === 32 && canonical === token ? { token, invalid: false } : { token: null, invalid: true };
  } catch {
    return { token: null, invalid: true };
  }
}

function clearToken() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  fragment.delete('enroll');
  const hash = fragment.size ? `#${fragment}` : '';
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${hash}`);
}

export function CredentialEnrollment({ id }: { id: string }) {
  const [descriptor, setDescriptor] = useState<CredentialDescriptor | null>(null);
  const [token, setToken] = useState(() => enrollmentToken());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  useEffect(() => {
    let active = true;
    void api<{ credential: CredentialDescriptor }>(`/credentials/${id}`)
      .then(value => {
        if (active) setDescriptor(value.credential);
      })
      .catch(cause => {
        if (active) setError(cause instanceof Error ? cause.message : 'Unable to load this credential group.');
      });
    return () => {
      active = false;
    };
  }, [id]);
  useEffect(() => {
    const update = () => setToken(enrollmentToken());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  async function enroll() {
    if (!token.token) return;
    setBusy(true);
    setError('');
    setNotice('');
    let saved: Awaited<ReturnType<typeof loadOrCreateGroupCredential>> | null = null;
    try {
      if (!descriptor) throw new Error('The credential group details could not be confirmed. Retry this link.');
      saved = await loadOrCreateGroupCredential(descriptor.id);
      await api(
        `/credentials/${descriptor.id}/enroll`,
        'POST',
        { token: token.token, commitment: saved.commitment },
      );
      await confirmGroupCredential(descriptor.id, descriptor.name, descriptor.description);
      clearToken();
      setToken({ token: null, invalid: false });
      setNotice('Credential saved and enrolled in this browser. It can now qualify for rooms that accept this group.');
    } catch (cause) {
      if (cause instanceof ApiError && cause.code === 'ENROLLMENT_INVITE_INVALID') {
        clearToken();
        setToken({ token: null, invalid: false });
        setError(cause.message);
      } else {
        setError(cause instanceof Error ? cause.message : 'Unable to enroll this browser credential.');
        if (saved) setNotice('The private credential is saved in this browser. If the server response was lost, retry this same link to complete enrollment.');
      }
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel join-page">
      <p className="eyebrow">CREDENTIAL ENROLLMENT</p>
      <h1>{descriptor?.name ?? 'Credential group'}</h1>
      <p>{descriptor?.description}</p>
      {error && <p role="alert" className="error">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {token.invalid && <p role="alert">This enrollment link could not be read. Ask the organizer for a new link.</p>}
      {!token.token && !token.invalid && !notice && (
        <p>This public page alone cannot enroll a credential. Open the organizer’s complete single use enrollment link.</p>
      )}
      {descriptor && (
        <>
          <p>
            A credential is saved in this browser before the organizer records enrollment.
            Saving does not grant access to any room.
          </p>
          <p className="muted">
            This credential stays in this browser. Clearing site data loses it; there is no recovery
            or transfer to another browser. The organizer can observe enrollment and network activity.
          </p>
          {!descriptor.available && (
            <p className="muted">This organizer session has expired, so this group can no longer accept new enrollments.</p>
          )}
          {token.token && (
            <button disabled={busy || !descriptor.available} onClick={() => void enroll()}>
              {busy ? 'Saving credential…' : 'Save credential in this browser'}
            </button>
          )}
        </>
      )}
    </section>
  );
}
