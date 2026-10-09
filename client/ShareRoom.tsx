import { useEffect, useState } from 'react';
import QRCode from 'qrcode';

export function ShareRoom({ code }: { code: string }) {
  const link = `${window.location.origin}/join/${code}`;
  const [image, setImage] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    let active = true;
    void QRCode.toDataURL(link, { width: 220, margin: 2, errorCorrectionLevel: 'M' })
      .then(value => { if (active) setImage(value); })
      .catch(() => { if (active) setMessage('QR could not load. Use the link below.'); });
    return () => { active = false; };
  }, [link]);

  async function copy() {
    try { await navigator.clipboard.writeText(link); setMessage('Link copied.'); }
    catch { setMessage('Select and copy the link below.'); }
  }

  return <section className="share-room" aria-labelledby="share-title">
    {image && <img src={image} alt="QR code for this room’s join link" width="180" height="180" />}
    <div><h2 id="share-title">Invite participants</h2>
      <p>Share this address. Each browser still needs your approval.</p>
      <a className="join-link" href={link}>{link}</a>
      <button type="button" className="secondary" onClick={() => void copy()}>Copy link</button>
      <p className="muted" role="status">{message}</p>
    </div>
  </section>;
}
