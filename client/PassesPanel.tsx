import { useEffect, useState, type FormEvent } from 'react';
import QRCode from 'qrcode';
import type { Room } from '../shared/rooms.js';
import { api, buildInvitationUrl, getPublicOrigin } from './api.js';

interface PassInfo {
  id: string;
  number: number;
  createdAt: string;
  revokedAt: string | null;
  redeemedAt: string | null;
  status: 'available' | 'used' | 'revoked' | 'expired';
}

interface IssuedPass extends PassInfo {
  token: string;
}

export function PassesPanel({
  room,
  fingerprint,
}: {
  room: Room;
  fingerprint: string | null;
}) {
  const [passes, setPasses] = useState<PassInfo[]>([]);
  const [batch, setBatch] = useState<IssuedPass[] | null>(null);
  const [selected, setSelected] = useState('');
  const [count, setCount] = useState(1);
  const [qr, setQr] = useState<{ url: string; image: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [listError, setListError] = useState('');
  const [actionError, setActionError] = useState('');
  const [message, setMessage] = useState('');

  const terminal = ['closed', 'expired'].includes(room.status);
  const selectedPass = batch?.find((pass) => pass.id === selected) ?? batch?.[0] ?? null;
  const currentSelected = selectedPass
    ? passes.find((pass) => pass.id === selectedPass.id)
    : null;
  const selectedUrl =
    selectedPass && currentSelected?.status === 'available' && !terminal
      ? buildInvitationUrl(
          getPublicOrigin(),
          room.joinCode,
          fingerprint,
          selectedPass.token,
        )
      : '';

  async function refresh() {
    try {
      const rows = await api<PassInfo[]>(`/rooms/${room.id}/passes`);
      setPasses(rows);
      setListError('');
    } catch (cause) {
      setListError(cause instanceof Error ? cause.message : 'Unable to load passes.');
    }
  }

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await refresh();
      if (active) timer = setTimeout(() => void poll(), 5_000);
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [room.id, room.status]);

  useEffect(() => {
    let active = true;
    if (!selectedUrl) {
      setQr(null);
      return;
    }
    void QRCode.toDataURL(selectedUrl, {
      width: 220,
      margin: 2,
      errorCorrectionLevel: 'M',
    })
      .then((image) => {
        if (active) setQr({ url: selectedUrl, image });
      })
      .catch(() => {
        if (active) setQr(null);
      });
    return () => {
      active = false;
    };
  }, [selectedUrl]);

  async function issue(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setActionError('');
    setMessage('');
    try {
      const result = await api<{ passes: IssuedPass[] }>(
        `/rooms/${room.id}/passes`,
        'POST',
        { count },
      );
      setBatch(result.passes);
      setSelected(result.passes[0]?.id ?? '');
      await refresh();
      setMessage(
        'New links are shown once. Save them before leaving. Portkey cannot recover them.',
      );
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : 'Unable to issue passes.';
      setActionError(
        `${detail} Check the pass list before trying again; an uncertain response may have created passes.`,
      );
    } finally {
      setBusy(false);
    }
  }

  async function copyLink() {
    if (!selectedUrl) return;
    setActionError('');
    setMessage('');
    try {
      await navigator.clipboard.writeText(selectedUrl);
      setMessage('Pass link copied.');
    } catch {
      setActionError('Clipboard access failed. Select the link and copy it manually.');
    }
  }

  function downloadCsv() {
    if (!batch) return;
    const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;
    const rows = batch.map((pass) => {
      const link = buildInvitationUrl(
        getPublicOrigin(),
        room.joinCode,
        fingerprint,
        pass.token,
      );
      return `${pass.number},${quote(link)}`;
    });
    const content = ['number,url', ...rows].join('\r\n');
    const url = URL.createObjectURL(
      new Blob([content], { type: 'text/csv;charset=utf-8' }),
    );
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `room-${room.id}-passes.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function revoke(pass: PassInfo) {
    if (!window.confirm(`Revoke unused pass ${pass.number}? This cannot be undone.`)) return;
    setBusy(true);
    setActionError('');
    setMessage('');
    try {
      await api(`/rooms/${room.id}/passes/${pass.id}`, 'PATCH', { status: 'revoked' });
      await refresh();
      setMessage(`Pass ${pass.number} revoked.`);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : 'Unable to revoke pass.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel passes-panel" aria-labelledby={`passes-${room.id}`}>
      <div className="panel-heading">
        <div>
          <h2 id={`passes-${room.id}`}>Admission passes</h2>
          <p>One pass admits one browser once. A recipient can forward it before redemption.</p>
        </div>
        <button className="secondary" type="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>
      {listError && <p role="alert" className="error passes-message">{listError}</p>}
      {actionError && <p role="alert" className="error passes-message">{actionError}</p>}
      {message && <p role="status" className="muted passes-message">{message}</p>}
      {!terminal && (
        <form className="pass-issue" onSubmit={(event) => void issue(event)}>
          <label>
            Number of passes
            <input
              type="number"
              min={1}
              max={20}
              step={1}
              value={count}
              onChange={(event) =>
                setCount(Math.max(1, Math.min(20, Number(event.target.value) || 1)))
              }
            />
          </label>
          <button disabled={busy || !!batch}>
            {busy ? 'Issuing…' : 'Generate passes'}
          </button>
        </form>
      )}
      {batch && (
        <div className="pass-batch">
          <div className="pass-batch-heading">
            <div>
              <h3>Save this batch now</h3>
              <p>These links will not appear again after you dismiss this batch.</p>
            </div>
            <button className="secondary" type="button" onClick={downloadCsv}>
              Download CSV
            </button>
          </div>
          <label>
            Select a pass
            <select value={selectedPass?.id ?? ''} onChange={(event) => setSelected(event.target.value)}>
              {batch.map((pass) => (
                <option key={pass.id} value={pass.id}>Pass {pass.number}</option>
              ))}
            </select>
          </label>
          <div className="pass-selected">
            {selectedUrl && qr?.url === selectedUrl && (
              <img
                src={qr.image}
                alt={`QR code for admission pass ${selectedPass?.number}`}
                width="156"
                height="156"
              />
            )}
            <div>
              {selectedUrl ? (
                <>
                  <a className="join-link" href={selectedUrl} target="_blank" rel="noopener noreferrer">
                    {selectedUrl}
                  </a>
                  <button type="button" className="secondary" onClick={() => void copyLink()}>
                    Copy pass link
                  </button>
                </>
              ) : (
                <p role="status">
                  This pass is {currentSelected?.status ?? 'unavailable'} and cannot be shared.
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            className="text-button"
            onClick={() => {
              setBatch(null);
              setSelected('');
              setQr(null);
              setActionError('');
            }}
          >
            Dismiss one-time links
          </button>
        </div>
      )}
      <div className="table-scroll">
        {passes.length === 0 ? (
          <p className="passes-empty">No passes have been issued.</p>
        ) : (
          <table>
            <thead>
              <tr><th>Pass</th><th>Issued</th><th>Status</th><th>Action</th></tr>
            </thead>
            <tbody>
              {passes.map((pass) => (
                <tr key={pass.id}>
                  <td>#{pass.number}</td>
                  <td>{new Date(pass.createdAt).toLocaleString()}</td>
                  <td>{pass.status}</td>
                  <td>
                    {!terminal && pass.status === 'available' ? (
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => void revoke(pass)}
                      >
                        Revoke
                      </button>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
