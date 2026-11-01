import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { PublicRoom } from '../shared/rooms.js';
import { departmentLabel, type CredentialFile } from '../shared/credentials.js';
import { api, requestFix } from './api.js';
import { credentialMatches, proveCredential, readCredential } from './credentialProof.js';
import { Icon, StatusBadge, formatDate, formatDistance } from './ui.js';

export function JoinPage({ code }: { code: string }) {
  const [room, setRoom] = useState<PublicRoom | null>(null);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [proving, setProving] = useState(false);
  const [locating, setLocating] = useState(false);
  const [credential, setCredential] = useState<CredentialFile | null>(null);
  const [credentialName, setCredentialName] = useState('');
  const [error, setError] = useState('');
  // Errors raised by an action must survive the 5-second status poll.
  const actionError = useRef(false);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const value = await api<PublicRoom>(`/join/${code}`);
        if (active) {
          setRoom(value);
          if (!actionError.current) setError('');
        }
      } catch (error) {
        if (active && !actionError.current)
          setError(error instanceof Error ? error.message : 'Unable to load room.');
      }
      if (active) timer = setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [code]);

  async function chooseCredential(file: File | undefined) {
    actionError.current = false;
    if (!file) {
      setCredential(null);
      setCredentialName('');
      return;
    }
    try {
      if (file.size > 16_384) throw new Error('The credential file is too large.');
      const parsed = readCredential(await file.text());
      if (room?.credential) credentialMatches(parsed, room.credential);
      setCredential(parsed);
      setCredentialName(file.name);
      setError('');
    } catch (error) {
      actionError.current = true;
      setCredential(null);
      setCredentialName('');
      setError(error instanceof Error ? error.message : 'Unable to read that credential.');
    }
  }

  async function join(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    actionError.current = false;
    setError('');
    try {
      const body: Record<string, unknown> = { label };
      if (room?.geo) {
        setLocating(true);
        try { Object.assign(body, await requestFix()); }
        finally { setLocating(false); }
      }
      if (room?.credential) {
        if (!credential) throw new Error('Choose your credential file first.');
        credentialMatches(credential, room.credential);
        setProving(true);
        const { challenge } = await api<{ challenge: string }>(`/join/${code}/challenge`, 'POST');
        body.credentialProof = await proveCredential(credential, room.id, challenge);
      }
      await api(`/join/${code}`, 'POST', body);
      setRoom(await api<PublicRoom>(`/join/${code}`));
      setError('');
    } catch (error) {
      actionError.current = true;
      setError(error instanceof Error ? error.message : 'Unable to request access.');
    } finally {
      setProving(false);
      setBusy(false);
    }
  }

  if (!room) return <p role={error ? 'alert' : 'status'}>{error || 'Finding room…'}</p>;
  return (
    <>
      <section className="panel join-page span-7">
        <div className="join-heading">
          <StatusBadge status={room.status} />
        </div>
        <h1>{room.title}</h1>
        <p className="join-lede">
          You’ve been invited.{room.description ? ` ${room.description}` : ''}
        </p>
        <p className="join-deadline">
          <Icon name="clock" />
          Access ends {formatDate(room.expiresAt)}
        </p>
        <p className="muted">
          After this deadline passes, the server removes the room’s shared files automatically.
        </p>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {room.status !== 'open' ? (
          <p>
            {room.status === 'draft'
              ? 'The organizer has not opened this room yet.'
              : 'This room has closed.'}
          </p>
        ) : room.isOwner || room.membershipStatus === 'approved' ? (
          <a className="button" href={`/rooms/${room.id}${window.location.hash}`}>
            Enter room
          </a>
        ) : room.membershipStatus === 'pending' && !room.credential ? (
          <p role="status">Waiting for organizer approval. This page updates automatically.</p>
        ) : room.membershipStatus === 'revoked' || room.membershipStatus === 'denied' ? (
          <p>The organizer has declined access for this browser.</p>
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
            {room.credential && (
              <div className="credential-upload">
                <p className="muted">
                  <Icon name="shield" /> This room admits{' '}
                  <strong>{departmentLabel(room.credential.dept)}</strong>, class of{' '}
                  <strong>{room.credential.year}</strong>. Bring the credential file your
                  institution issued you; a valid proof admits you immediately.
                </p>
                <label>
                  Credential file
                  <input
                    type="file"
                    accept="application/json,.json"
                    onChange={(event) => void chooseCredential(event.target.files?.[0])}
                  />
                </label>
                <p className="muted">
                  {credential
                    ? `${credentialName} · ${departmentLabel(credential.attributes.dept)} · class of ${credential.attributes.year}`
                    : 'The proof is generated in this browser. The file, its secret and the issuer signature never leave this device.'}
                </p>
              </div>
            )}
            {room.geo ? (
              <p className="muted">
                <Icon name="shield" /> This room is restricted to {formatDistance(room.geo.radiusM)}{' '}
                around {room.geoLabel ?? 'a set area'}. Your device location is required and checked
                on every visit; you cannot request access without it.
              </p>
            ) : (
              <p className="muted">
                Use a label the organizer can recognize. No email, roll number, or external ID is
                required.
              </p>
            )}
            <button disabled={busy || (Boolean(room.credential) && !credential)}>
              {locating
                ? 'Getting precise location…'
                : proving
                ? 'Generating proof…'
                : busy
                  ? 'Requesting…'
                  : room.credential
                    ? 'Prove eligibility & request access'
                    : room.geo
                      ? 'Share location & request access'
                      : 'Request access'}
            </button>
          </form>
        )}
      </section>
      <figure className="media tall span-5 start-8">
        <img
          src="/photos/set-old-keys-hanging-wall.webp"
          alt="Bunches of old iron keys hanging on a dark wooden wall"
          width="1024"
          height="683"
          loading="lazy"
        />
        <figcaption>
          <strong>One key per invitation</strong>
          <span>Markus Spiske</span>
        </figcaption>
      </figure>
    </>
  );
}
