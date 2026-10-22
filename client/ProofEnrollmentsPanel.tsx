import { useEffect, useState, type FormEvent } from 'react';
import QRCode from 'qrcode';
import type { Room } from '../shared/rooms.js';
import { api, ApiError, buildWorkshopEnrollmentUrl, getPublicOrigin } from './api.js';

interface EnrollmentInfo {
  id: string;
  number: number;
  createdAt: string;
  revokedAt: string | null;
  status: 'available' | 'enrolled' | 'revoked' | 'expired';
}

interface IssuedEnrollment extends EnrollmentInfo {
  token: string;
}

export function ProofEnrollmentsPanel({ room, fingerprint }: { room: Room; fingerprint: string | null }) {
  const [enrollments, setEnrollments] = useState<EnrollmentInfo[]>([]);
  const [counts, setCounts] = useState({ enrolled: 0, available: 0, revoked: 0 });
  const [batch, setBatch] = useState<IssuedEnrollment[] | null>(null);
  const [selectedId, setSelectedId] = useState('');
  const [count, setCount] = useState(1);
  const [qr, setQr] = useState<{ url: string; image: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [listError, setListError] = useState('');
  const [actionError, setActionError] = useState('');
  const [message, setMessage] = useState('');
  const terminal = ['closed', 'expired'].includes(room.status);
  const selected = batch?.find((item) => item.id === selectedId) ?? batch?.[0] ?? null;
  const current = selected ? enrollments.find((item) => item.id === selected.id) : null;
  const selectedUrl = selected && current?.status === 'available' && !terminal
    ? buildWorkshopEnrollmentUrl(getPublicOrigin(), room.joinCode, fingerprint, selected.token)
    : '';

  async function refresh() {
    try {
      const result = await api<{ enrollments: EnrollmentInfo[]; counts: typeof counts }>(`/rooms/${room.id}/enrollments`);
      setEnrollments(result.enrollments);
      setCounts(result.counts);
      setListError('');
    } catch (error) {
      setListError(error instanceof Error ? error.message : 'Unable to load enrollment links.');
    }
  }

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await refresh();
      if (active) timer = setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [room.id]);

  useEffect(() => {
    let active = true;
    if (!selectedUrl) {
      setQr(null);
      return;
    }
    void QRCode.toDataURL(selectedUrl, { width: 240, margin: 2, errorCorrectionLevel: 'M' })
      .then((image) => { if (active) setQr({ url: selectedUrl, image }); })
      .catch(() => { if (active) setQr(null); });
    return () => { active = false; };
  }, [selectedUrl]);

  async function issue(event: FormEvent) {
    event.preventDefault();
    if (batch && !window.confirm('Replace the enrollment links displayed in this tab? Any unused links in that batch will still work, but the links cannot be shown again after you replace them.')) return;
    setBusy(true);
    setActionError('');
    setMessage('');
    try {
      const result = await api<{ enrollments: IssuedEnrollment[] }>(`/rooms/${room.id}/enrollments`, 'POST', { count });
      setBatch(result.enrollments);
      setSelectedId(result.enrollments[0]?.id ?? '');
      setMessage('New enrollment links are displayed once. Save the links or download the CSV now.');
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to issue enrollment links.');
      if (!(error instanceof ApiError) || error.status >= 500)
        setMessage('The request may have reached the server. Refresh the enrollment list before retrying. Any issued links cannot be recovered; revoke unused links if needed.');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    setBusy(true);
    setActionError('');
    try {
      await api(`/rooms/${room.id}/enrollments/${id}`, 'PATCH', { status: 'revoked' });
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to revoke this enrollment link.');
    } finally {
      setBusy(false);
    }
  }

  function downloadCsv() {
    if (!batch) return;
    const rows = [['Enrollment', 'Link'], ...batch.map((item) => [String(item.number), buildWorkshopEnrollmentUrl(getPublicOrigin(), room.joinCode, fingerprint, item.token)])];
    const csv = rows.map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `workshop-enrollment-${room.id}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage('CSV downloaded. Keep it private; each link can enroll one credential.');
  }

  function dismissBatch() {
    if (!window.confirm('Hide the displayed enrollment tokens? Unused links remain valid but cannot be shown again. Download the CSV first if needed.')) return;
    setBatch(null);
    setSelectedId('');
    setQr(null);
    setMessage('Displayed tokens were cleared from this tab. Unused links remain valid until revoked or the room closes.');
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(selectedUrl);
      setMessage('Enrollment link copied. Share it privately with the intended attendee.');
    } catch {
      setMessage('Select and copy the enrollment link below.');
    }
  }

  return (
    <section className="panel proof-enrollments" aria-labelledby="enrollment-title">
      <div className="panel-heading">
        <div>
          <h2 id="enrollment-title">Workshop credential enrollment</h2>
          <p>{counts.enrolled} enrolled · {counts.available} unused · {counts.revoked} revoked</p>
        </div>
      </div>
      <p>Issue a single-use enrollment QR or link for each attendee. Saving a credential does not grant room access; the attendee must later prove membership.</p>
      <p className="muted">Each link can be forwarded until used. The enrollment service sees each commitment and can observe browser and network activity. The membership proof hides which commitment is used, but browser activity may still be linked. Groups of fewer than three have little cover. A credential stays in its browser; clearing browser data loses it, with no recovery or transfer.</p>
      {listError && <p role="alert" className="error">{listError}</p>}
      {actionError && <p role="alert" className="error">{actionError}</p>}
      {room.status === 'draft' || room.status === 'open' ? (
        <form className="enrollment-issue" onSubmit={(event) => void issue(event)}>
          <label>
            Number of enrollment links
            <input type="number" min={1} max={20} value={count} onChange={(event) => setCount(Number(event.target.value))} />
          </label>
          <button disabled={busy || !Number.isInteger(count) || count < 1 || count > 20}>{busy ? 'Issuing…' : 'Issue enrollment links'}</button>
        </form>
      ) : <p className="muted">Enrollment links cannot be issued or revoked after this room closes.</p>}
      {batch && (
        <div className="enrollment-batch">
          <label>
            Enrollment link
            <select value={selected?.id ?? ''} onChange={(event) => setSelectedId(event.target.value)}>
              {batch.map((item) => <option key={item.id} value={item.id}>Enrollment {item.number}</option>)}
            </select>
          </label>
          {selectedUrl && (
            <>
              {qr?.url === selectedUrl && <img className="enrollment-qr" src={qr.image} alt={`QR code for enrollment ${selected?.number}`} />}
              <a className="join-link" href={selectedUrl} target="_blank" rel="noopener noreferrer">{selectedUrl}</a>
            </>
          )}
          <div className="actions">
            {selectedUrl && <button type="button" className="secondary" onClick={() => void copy()}>Copy selected link</button>}
            <button type="button" className="secondary" onClick={downloadCsv}>Download CSV</button>
            <button type="button" className="secondary" onClick={dismissBatch}>Hide displayed tokens</button>
          </div>
        </div>
      )}
      {message && <p role="status" className="muted">{message}</p>}
      <button type="button" className="secondary" onClick={() => void refresh()}>Refresh enrollment list</button>
      {enrollments.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Enrollment</th><th>Created</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
              {enrollments.map((item) => (
                <tr key={item.id}>
                  <td>{item.number}</td>
                  <td>{new Date(item.createdAt).toLocaleString()}</td>
                  <td>{item.status}</td>
                  <td>{item.status === 'available' && !terminal ? <button className="secondary" disabled={busy} onClick={() => void revoke(item.id)}>Revoke unused link</button> : item.status === 'enrolled' ? 'This link cannot revoke a saved credential. Remove browser access after admission.' : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
