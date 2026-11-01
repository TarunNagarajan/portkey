import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { Icon } from './ui.js';

export function ShareRoom({ code, fingerprint, roomAccess }: { code: string; fingerprint?: string | null; roomAccess?: string | null }) {
  const fragment = new URLSearchParams();
  if (fingerprint) fragment.set('key', fingerprint);
  if (roomAccess) fragment.set('access', roomAccess);
  const link = `${window.location.origin}/join/${code}${fragment.size ? `#${fragment}` : ''}`;
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
      setMessage('Open the invitation and copy its address.');
    }
  }

  return (
    <section className="panel share-room" data-ui aria-labelledby="share-title">
      <div className="qr-frame">
        {image && (
          <img src={image} alt="QR code for this room’s join link" width="156" height="156" />
        )}
        <span>Scan to request access</span>
      </div>
      <div>
        <h2 id="share-title">Invite participants</h2>
        <p>Share this address through a channel participants can trust. Each browser still needs approval or a valid credential proof.</p>
        <a className="join-link" href={link}>
          Open room invitation
        </a>
        <button type="button" className="secondary" onClick={() => void copy()}>
          <Icon name="copy" />
          Copy link
        </button>
        <p className="muted" role="status">
          {message}
        </p>
      </div>
    </section>
  );
}
