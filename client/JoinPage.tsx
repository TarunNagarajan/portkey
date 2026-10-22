import { useEffect, useState, type FormEvent } from 'react';
import type { PublicRoom } from '../shared/rooms.js';
import { api, ApiError, requestFix } from './api.js';
import { Icon, StatusBadge, formatDate, formatDistance } from './ui.js';
import { ReusableAdmission } from './ReusableAdmission.js';

function readPassFragment(): { token: string | null; invalid: boolean } {
  const values = new URLSearchParams(window.location.hash.slice(1)).getAll('pass');
  if (values.length === 0) return { token: null, invalid: false };
  const token = values[0];
  if (values.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(token))
    return { token: null, invalid: true };
  try {
    const decoded = atob(token.replaceAll('-', '+').replaceAll('_', '/') + '=');
    const canonical = btoa(decoded).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
    return canonical === token && decoded.length === 32
      ? { token, invalid: false }
      : { token: null, invalid: true };
  } catch {
    return { token: null, invalid: true };
  }
}

function removePassFragment() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  fragment.delete('pass');
  const hash = fragment.size ? `#${fragment.toString()}` : '';
  window.history.replaceState(
    null,
    '',
    `${window.location.pathname}${window.location.search}${hash}`,
  );
}

function inboxKeyFragment() {
  const key = new URLSearchParams(window.location.hash.slice(1)).get('key');
  return key && /^[a-f0-9]{64}$/.test(key) ? `#key=${encodeURIComponent(key)}` : '';
}

export function JoinPage({ code }: { code: string }) {
  const [room, setRoom] = useState<PublicRoom | null>(null);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [actionError, setActionError] = useState('');
  const [passToken, setPassToken] = useState(() => readPassFragment().token);
  const [invalidPass, setInvalidPass] = useState(() => readPassFragment().invalid);

  useEffect(() => {
    function updatePassFromFragment() {
      const pass = readPassFragment();
      setPassToken(pass.token);
      setInvalidPass(pass.invalid);
      if (pass.token) setActionError('');
    }
    window.addEventListener('hashchange', updatePassFromFragment);
    return () => window.removeEventListener('hashchange', updatePassFromFragment);
  }, []);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const value = await api<PublicRoom>(`/join/${code}`);
        if (active) {
          setRoom(value);
          setLoadError('');
        }
      } catch (error) {
        if (active) setLoadError(error instanceof Error ? error.message : 'Unable to load room.');
      }
      if (active) timer = setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [code]);

  useEffect(() => {
    if (room && (room.isOwner || room.membershipStatus === 'approved') && passToken) {
      removePassFragment();
      setPassToken(null);
    }
  }, [room, passToken]);

  async function join(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setActionError('');
    try {
      const body: Record<string, unknown> = { label };
      if (room?.geo) Object.assign(body, await requestFix());
      if (room?.admissionPolicy === 'pass') {
        if (!passToken)
          throw new Error(
            'Ask the organizer for a pass link. This room does not accept ordinary access requests.',
          );
        const member = await api<{ status: string }>(`/join/${code}/redeem`, 'POST', {
          ...body,
          token: passToken,
        });
        if (member.status === 'approved') {
          removePassFragment();
          setPassToken(null);
          setInvalidPass(false);
        }
      } else {
        await api(`/join/${code}`, 'POST', body);
      }
      setRoom(await api<PublicRoom>(`/join/${code}`));
    } catch (error) {
      if (error instanceof ApiError && error.code === 'ADMISSION_PASS_INVALID') {
        removePassFragment();
        setPassToken(null);
        setInvalidPass(true);
      }
      setActionError(error instanceof Error ? error.message : 'Unable to request access.');
    } finally {
      setBusy(false);
    }
  }

  if (!room) return <p role={loadError || actionError ? 'alert' : 'status'}>{actionError || loadError || 'Finding room…'}</p>;
  return (
    <section className="panel join-page">
      <div className="join-heading">
        <span className="empty-symbol">
          <Icon name="rooms" />
        </span>
        <StatusBadge status={room.status} />
      </div>
      <p className="eyebrow">YOU’RE INVITED</p>
      <h1>{room.title}</h1>
      <p>{room.description}</p>
      <p className="join-deadline">
        <Icon name="clock" />
        Access ends {formatDate(room.expiresAt)}
      </p>
      <p className="muted">
        {room.submissionCleanupEnabled
          ? room.submissionsPurgedAt
            ? 'The server has removed encrypted submissions for this room.'
            : 'Completed encrypted submissions are scheduled for removal after this deadline, usually within a minute while running and longer with a backlog or downtime. Unfinished uploads are removed after 24 hours.'
          : 'Automatic room deadline cleanup is disabled. Incomplete uploads are still removed after 24 hours.'}
      </p>
      {loadError && (
        <p role="alert" className="error">
          {loadError}
        </p>
      )}
      {actionError && (
        <p role="alert" className="error">
          {actionError}
        </p>
      )}
      {room.status !== 'open' ? (
        <p>
          {room.status === 'draft'
            ? 'The organizer has not opened this room yet.'
            : 'This room has closed.'}
        </p>
      ) : room.isOwner || room.membershipStatus === 'approved' ? (
        <a className="button" href={`/rooms/${room.id}${inboxKeyFragment()}`}>
          Enter room
        </a>
      ) : room.membershipStatus === 'pending' && room.admissionPolicy === 'approval' ? (
        <p role="status">Waiting for organizer approval. This page updates automatically.</p>
      ) : room.membershipStatus === 'revoked' || room.membershipStatus === 'denied' ? (
        <p>The organizer has declined access for this browser.</p>
      ) : room.admissionPolicy === 'proof' ? (
        <ReusableAdmission
          room={room}
          code={code}
          onAdmitted={() => {
            window.location.assign(`/rooms/${room.id}${inboxKeyFragment()}`);
          }}
        />
      ) : room.admissionPolicy === 'pass' && !passToken ? (
        <p>
          {invalidPass
            ? 'This pass could not be used. Ask the organizer for a new pass.'
            : 'Ask the organizer for a single use admission pass. This public room link does not grant access.'}
        </p>
      ) : (
        <form onSubmit={join}>
          <label>
            Your label
            <input
              required
              maxLength={50}
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              placeholder="A nickname or team label"
            />
          </label>
          {room.geo ? (
            <p className="muted">
              <Icon name="shield" /> This room is restricted to{' '}
              {formatDistance(room.geo.radiusM)} around {room.geoLabel ?? 'a set area'}. Your device
              location is required and checked on every visit; you cannot request access without it.
            </p>
          ) : (
            <p className="muted">
              Use a label the organizer can recognize. No email, roll number, or external ID is
              required.
            </p>
          )}
          {room.admissionPolicy === 'pass' && (
            <p className="muted">
              A pass is used once and binds access to this browser. Anyone holding the link can
              redeem it before you do.
            </p>
          )}
          <button disabled={busy}>
            {busy
              ? room.admissionPolicy === 'pass' ? 'Redeeming…' : 'Requesting…'
              : room.geo
                ? room.admissionPolicy === 'pass'
                  ? 'Share location & redeem pass'
                  : 'Share location & request access'
                : room.admissionPolicy === 'pass'
                  ? 'Redeem pass'
                  : 'Request access'}
          </button>
        </form>
      )}
    </section>
  );
}
