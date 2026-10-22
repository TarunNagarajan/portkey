import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { PublicRoom } from '../shared/rooms.js';
import { WORKSHOP_PROOF_VERSION } from '../shared/workshopProof.js';
import { api, ApiError, requestFix } from './api.js';
import { generateWorkshopProof, submitProofWithBusyRetry, type WorkshopChallenge } from './workshopProof.js';
import { getOrCreateWorkshopIdentity, loadWorkshopIdentity, resetWorkshopIdentity, type WorkshopIdentity } from './workshopIdentity.js';

function readEnrollmentFragment(): { token: string | null; invalid: boolean } {
  const values = new URLSearchParams(window.location.hash.slice(1)).getAll('enroll');
  if (values.length === 0) return { token: null, invalid: false };
  const token = values[0];
  if (values.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(token)) return { token: null, invalid: true };
  try {
    const decoded = atob(token.replaceAll('-', '+').replaceAll('_', '/') + '=');
    const canonical = btoa(decoded).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    return canonical === token && decoded.length === 32 ? { token, invalid: false } : { token: null, invalid: true };
  } catch {
    return { token: null, invalid: true };
  }
}

function removeEnrollmentFragment() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  fragment.delete('enroll');
  const hash = fragment.size ? `#${fragment.toString()}` : '';
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${hash}`);
}

export function WorkshopAdmission({ room, code, onAdmitted }: {
  room: PublicRoom;
  code: string;
  onAdmitted: () => void;
}) {
  const [identity, setIdentity] = useState<WorkshopIdentity | null>(null);
  const [identityLoading, setIdentityLoading] = useState(true);
  const [identityError, setIdentityError] = useState('');
  const [enrollment, setEnrollment] = useState(() => readEnrollmentFragment());
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState<'enroll' | 'prove' | null>(null);
  const [actionError, setActionError] = useState('');
  const [notice, setNotice] = useState('');
  const [groupSize, setGroupSize] = useState<number | null>(null);
  const proofController = useRef<AbortController | null>(null);

  useEffect(() => {
    let active = true;
    void loadWorkshopIdentity(room.id)
      .then((saved) => { if (active) setIdentity(saved); })
      .catch((error) => { if (active) setIdentityError(error instanceof Error ? error.message : 'Could not read the saved workshop credential.'); })
      .finally(() => { if (active) setIdentityLoading(false); });
    return () => { active = false; };
  }, [room.id]);

  useEffect(() => () => proofController.current?.abort(), [room.id]);

  useEffect(() => {
    const update = () => setEnrollment(readEnrollmentFragment());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);

  async function saveCredential() {
    if (!enrollment.token) return;
    setBusy('enroll');
    setActionError('');
    setNotice('');
    let saved = identity;
    let confirmedInvalid = false;
    try {
      saved ??= await getOrCreateWorkshopIdentity(room.id);
      setIdentity(saved);
      setIdentityError('');
      await api(`/join/${code}/enroll`, 'POST', { token: enrollment.token, commitment: saved.commitment });
      removeEnrollmentFragment();
      setEnrollment({ token: null, invalid: false });
      setNotice('Credential saved and enrolled in this browser. Prove membership to enter the workshop.');
    } catch (error) {
      confirmedInvalid = error instanceof ApiError && error.code === 'ENROLLMENT_INVITE_INVALID';
      if (saved) {
        setIdentity(saved);
        if (confirmedInvalid) {
          removeEnrollmentFragment();
          setEnrollment({ token: null, invalid: false });
        }
        setNotice(confirmedInvalid
          ? 'Your credential is saved in this browser, but this link cannot enroll it. You can still try proving membership; if it was not enrolled, ask the organizer for a new link.'
          : 'Your credential is saved in this browser. The enrollment request did not confirm; retry this link before closing the page.');
      }
      setActionError(error instanceof Error ? error.message : 'Could not save the workshop credential.');
    } finally {
      setBusy(null);
    }
  }

  async function prove(event: FormEvent) {
    event.preventDefault();
    if (!identity) return;
    setBusy('prove');
    setActionError('');
    setNotice('');
    const controller = new AbortController();
    proofController.current = controller;
    try {
      const challenge = await api<WorkshopChallenge>(`/join/${code}/proof-challenge`, 'POST', {}, controller.signal);
      setGroupSize(challenge.commitments.length);
      if (challenge.version !== WORKSHOP_PROOF_VERSION || Date.parse(challenge.expiresAt) <= Date.now())
        throw new Error('This workshop proof challenge has expired or uses an unsupported version. Refresh and try again.');
      const proof = await generateWorkshopProof(identity.exportedIdentity, challenge, controller.signal);
      const location = room.geo ? await requestFix() : null;
      const body: Record<string, unknown> = { challengeId: challenge.challengeId, proof };
      if (label.trim()) body.label = label.trim();
      if (location) Object.assign(body, location);
      await submitProofWithBusyRetry(code, body, controller.signal, Date.parse(challenge.expiresAt));
      onAdmitted();
    } catch (error) {
      if (error instanceof ApiError && error.code === 'ADMISSION_DENIED') {
        setActionError(error.message);
      } else {
        setActionError(error instanceof Error ? error.message : 'Unable to prove workshop membership.');
      }
    } finally {
      proofController.current = null;
      setBusy(null);
    }
  }

  async function resetCredential() {
    if (!window.confirm('Delete only this workshop’s saved credential from this browser? You cannot recover it. If it was already enrolled, ask the organizer for a new enrollment link.')) return;
    try {
      await resetWorkshopIdentity(room.id);
      setIdentity(null);
      setIdentityError('');
      setActionError('');
      setNotice('This workshop credential was removed from this browser. Save a new enrollment link to enroll again.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not reset this workshop credential.');
    }
  }

  return (
    <section className="workshop-admission" aria-labelledby="workshop-admission-title">
      <h2 id="workshop-admission-title">Workshop credential</h2>
      {actionError && <p role="alert" className="error">{actionError}</p>}
      {notice && <p role="status">{notice}</p>}
      {identityLoading ? <p role="status">Checking this browser for a saved credential…</p> : null}
      {identityError && <p role="alert" className="error">{identityError}</p>}
      {identityError && !identityLoading && <button type="button" className="secondary" onClick={() => void resetCredential()}>Reset saved credential for this workshop</button>}
      {enrollment.invalid && !identity ? (
        <p role="alert">This enrollment link could not be read. Ask the organizer for a new enrollment link.</p>
      ) : enrollment.token ? (
        <>
          <p>Save a room-specific credential in this browser. The enrollment service receives its public commitment; saving does not admit you to the room.</p>
          <button type="button" disabled={busy !== null || identityLoading || !!identityError} onClick={() => void saveCredential()}>
            {busy === 'enroll' ? 'Saving credential…' : identity ? 'Save or retry enrollment' : 'Save workshop credential'}
          </button>
        </>
      ) : identity ? (
        <>
          <p>This browser has a saved credential for this workshop. The proof shows that you are enrolled without naming your enrollment record. Browser and network activity may still identify you.</p>
          <p className="muted">Small groups offer little privacy, especially when fewer than three people enroll.</p>
          {groupSize !== null && groupSize < 3 && <p className="muted">There are {groupSize} enrolled credentials. This group is too small to provide meaningful privacy.</p>}
          {room.geo && <p className="muted">This workshop checks your device location during admission. Your coordinates are sent with the proof request and checked against the room area.</p>}
          <form onSubmit={(event) => void prove(event)}>
            <label>
              Nickname (optional)
              <input maxLength={50} value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Workshop attendee" />
            </label>
            <button disabled={busy !== null}>{busy === 'prove' ? 'Checking membership…' : room.geo ? 'Share location and prove membership' : 'Prove membership and enter'}</button>
          </form>
          <p className="muted">The credential stays in this browser. Clearing browser data loses it; there is no recovery or transfer. Browser storage is accessible to scripts running on this site.</p>
        </>
      ) : (
        <p>{identityError ? 'This browser could not read a saved credential.' : 'This public room link does not grant access. Scan the organizer’s enrollment QR to save a workshop credential first.'} The credential is local to this browser and cannot be recovered if its site data is cleared.</p>
      )}
    </section>
  );
}
