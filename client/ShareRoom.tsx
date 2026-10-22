import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { Icon } from './ui.js';
import { buildInvitationUrl, getPublicOrigin, isLocalOrigin } from './api.js';

export function ShareRoom({ code, fingerprint, passMode = false }: { code: string; fingerprint?: string | null; passMode?: boolean }) {
  const link = buildInvitationUrl(getPublicOrigin(), code, fingerprint);
  const [image, setImage] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;
    void QRCode.toDataURL(link, { width: 220, margin: 2, errorCorrectionLevel: 'M' })
      .then((value) => {
        if (active) setImage(value);
      })
      .catch(() => {
        if (active) setMessage('QR could not load. Use the link below.');
      });
    return () => {
      active = false;
    };
  }, [link]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(link);
      setMessage('Link copied.');
    } catch {
      setMessage('Select and copy the link below.');
    }
  }

  return (
    <section className="panel share-room" aria-labelledby="share-title">
      <div className="qr-frame">
        {image && (
          <img src={image} alt="QR code for this room’s join link" width="156" height="156" />
        )}
        <span>{passMode ? 'SCAN FOR ROOM PREVIEW' : 'SCAN TO REQUEST ACCESS'}</span>
      </div>
      <div>
        <h2 id="share-title">{passMode ? 'Room preview link' : 'Invite participants'}</h2>
        <p>{passMode ? 'This room address shows a public preview. Admission requires a separate one use pass from you.' : 'Share this address through a channel participants can trust. Each browser still needs your approval.'}</p>
        {isLocalOrigin(getPublicOrigin()) && <p className="muted">This local address is for this computer. Phone sharing needs a public HTTPS address.</p>}
        {fingerprint && <p className="muted">Inbox key fingerprint: <code>{fingerprint}</code></p>}
        <a className="join-link" href={link}>
          {link}
        </a>
        <button type="button" className="secondary" onClick={() => void copy()}>
          <Icon name="copy" />
          {passMode ? 'Copy preview link' : 'Copy link'}
        </button>
        <p className="muted" role="status">
          {message}
        </p>
      </div>
    </section>
  );
}
