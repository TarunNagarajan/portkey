import { useEffect, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import {
  api,
  ApiError,
  buildCredentialEnrollmentUrl,
  getPublicOrigin,
} from "./api.js";

interface CredentialGroup {
  id: string;
  name: string;
  description: string;
  enrolledCount: number;
  available: boolean;
  availableUntil: string | null;
  persistent?: boolean;
  createdAt?: string;
}

interface Enrollment {
  id: string;
  number: number;
  createdAt: string;
  revokedAt: string | null;
  status: "available" | "enrolled" | "revoked";
}

interface IssuedEnrollment extends Enrollment {
  token: string;
}

export function CredentialGroups() {
  const [groups, setGroups] = useState<CredentialGroup[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      const result = await api<{ groups: CredentialGroup[] }>(
        "/credential-groups",
      );
      setGroups(result.groups);
      setError("");
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to load credential groups.",
      );
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function create(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const group = await api<CredentialGroup>("/credential-groups", "POST", {
        name,
        description,
      });
      window.location.assign(`/credential-groups/${group.id}`);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to create the credential group.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">ORGANIZER</p>
          <h1>Credential groups</h1>
          <p>
            Enroll people once, then let proof rooms accept any selected group.
          </p>
        </div>
      </header>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <section className="panel credential-panel">
        <h2>Your groups</h2>
        {groups.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Enrolled</th>
                  <th>Available until</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((group) => (
                  <tr key={group.id}>
                    <td>
                      <a href={`/credential-groups/${group.id}`}>
                        {group.name}
                      </a>
                    </td>
                    <td>{group.enrolledCount}</td>
                    <td>
                      {group.persistent
                        ? "Persistent"
                        : group.availableUntil
                          ? new Date(group.availableUntil).toLocaleDateString()
                          : "Unavailable"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p>
            No reusable groups yet. Create one to enroll a credential that can
            qualify for several rooms.
          </p>
        )}
      </section>
      <section className="panel credential-panel">
        <h2>Create a credential group</h2>
        <p>
          Groups last as long as this organizer browser session, which expires
          after 30 days. This prototype does not provide permanent organizer
          accounts.
        </p>
        <form onSubmit={(event) => void create(event)}>
          <label>
            Group name
            <input
              required
              maxLength={80}
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Workshop attendees"
            />
          </label>
          <label>
            Description
            <textarea
              maxLength={300}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </label>
          <button disabled={busy}>{busy ? "Creating…" : "Create group"}</button>
        </form>
      </section>
    </>
  );
}

export function CredentialGroupDetail({ id }: { id: string }) {
  const [group, setGroup] = useState<CredentialGroup | null>(null);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [counts, setCounts] = useState({
    enrolled: 0,
    available: 0,
    revoked: 0,
  });
  const [batch, setBatch] = useState<IssuedEnrollment[] | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [count, setCount] = useState(1);
  const [qr, setQr] = useState<{ url: string; image: string } | null>(null);
  const [listError, setListError] = useState("");
  const [actionError, setActionError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const selected =
    batch?.find((item) => item.id === selectedId) ?? batch?.[0] ?? null;
  const current =
    selected && enrollments.find((item) => item.id === selected.id);
  const selectedUrl =
    selected && current?.status === "available" && group?.available
      ? buildCredentialEnrollmentUrl(getPublicOrigin(), id, selected.token)
      : "";

  async function refresh() {
    try {
      const value = await api<{
        group: CredentialGroup;
        enrollments: Enrollment[];
        counts: typeof counts;
      }>(`/credential-groups/${id}`);
      setGroup(value.group);
      setEnrollments(value.enrollments);
      setCounts(value.counts);
      setListError("");
    } catch (cause) {
      setListError(
        cause instanceof Error
          ? cause.message
          : "Unable to load this credential group.",
      );
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
  }, [id]);

  useEffect(() => {
    let active = true;
    if (!selectedUrl) {
      setQr(null);
      return;
    }
    void QRCode.toDataURL(selectedUrl, {
      width: 240,
      margin: 2,
      errorCorrectionLevel: "M",
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
    if (
      batch &&
      !window.confirm(
        "Replace the links displayed in this tab? Unused links remain valid, but their tokens cannot be shown again.",
      )
    )
      return;
    setBusy(true);
    setActionError("");
    setMessage("");
    try {
      const value = await api<{ enrollments: IssuedEnrollment[] }>(
        `/credential-groups/${id}/enrollments`,
        "POST",
        { count },
      );
      setBatch(value.enrollments);
      setSelectedId(value.enrollments[0]?.id ?? "");
      setMessage(
        "These links are shown once. Save or download them before hiding this batch.",
      );
      await refresh();
    } catch (cause) {
      setActionError(
        cause instanceof Error
          ? cause.message
          : "Unable to issue enrollment links.",
      );
      if (!(cause instanceof ApiError) || cause.status >= 500) {
        setMessage(
          "The request may have reached the server. Refresh the enrollment list before retrying; issued tokens cannot be recovered.",
        );
      }
    } finally {
      setBusy(false);
    }
  }

  async function revoke(inviteId: string) {
    setBusy(true);
    setActionError("");
    try {
      await api(`/credential-groups/${id}/enrollments/${inviteId}`, "PATCH", {
        status: "revoked",
      });
      await refresh();
    } catch (cause) {
      setActionError(
        cause instanceof Error ? cause.message : "Unable to revoke this link.",
      );
    } finally {
      setBusy(false);
    }
  }

  function downloadCsv() {
    if (!batch) return;
    const rows = [
      ["Enrollment", "Link"],
      ...batch.map((item) => [
        String(item.number),
        buildCredentialEnrollmentUrl(getPublicOrigin(), id, item.token),
      ]),
    ];
    const csv = rows
      .map((row) =>
        row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(","),
      )
      .join("\r\n");
    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `credential-enrollments-${id}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
    setMessage(
      "CSV downloaded. Keep it private; each link enrolls one browser credential.",
    );
  }

  function dismiss() {
    if (
      !window.confirm(
        "Hide the displayed tokens? Unused links remain valid but cannot be shown again.",
      )
    )
      return;
    setBatch(null);
    setSelectedId("");
    setQr(null);
    setMessage(
      "Displayed tokens were cleared from this tab. Unused links remain valid until revoked or the organizer session expires.",
    );
  }

  return (
    <>
      <a href="/credential-groups" className="back-link">
        Back to credential groups
      </a>
      <header className="page-heading">
        <div>
          <p className="eyebrow">ORGANIZER</p>
          <h1>{group?.name ?? "Credential group"}</h1>
          <p>{group?.description}</p>
        </div>
      </header>
      {listError && (
        <p role="alert" className="error">
          {listError}
        </p>
      )}
      {actionError && (
        <p role="alert" className="error">
          {actionError}
        </p>
      )}
      {group && (
        <>
          <section className="panel credential-panel">
            <h2>Enrollment</h2>
            <p>
              {counts.enrolled} enrolled · {counts.available} unused ·{" "}
              {counts.revoked} revoked
            </p>
            <p>
              Issue a one use QR or link for each attendee. Enrollment stores a
              browser credential; it does not grant room access.
            </p>
            <p className="muted">
              The organizer can see which credentials enrolled in this group.
              Proofs hide which credential qualifies, but browser and network
              activity can still be linked. Groups of fewer than three people
              offer little cover. Credentials stay in this browser; clearing
              site data loses them.
            </p>
            <form
              className="enrollment-issue"
              onSubmit={(event) => void issue(event)}
            >
              <label>
                Number of enrollment links
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={count}
                  onChange={(event) => setCount(Number(event.target.value))}
                />
              </label>
              <button
                disabled={
                  busy ||
                  !group.available ||
                  !Number.isInteger(count) ||
                  count < 1 ||
                  count > 20
                }
              >
                {busy ? "Issuing…" : "Issue enrollment links"}
              </button>
            </form>
            {!group.available && (
              <p className="muted">
                This organizer session has expired. New enrollment links cannot
                be issued.
              </p>
            )}
            {batch && (
              <div className="enrollment-batch">
                <label>
                  Enrollment link
                  <select
                    value={selected?.id ?? ""}
                    onChange={(event) => setSelectedId(event.target.value)}
                  >
                    {batch.map((item) => (
                      <option key={item.id} value={item.id}>
                        Enrollment {item.number}
                      </option>
                    ))}
                  </select>
                </label>
                {selectedUrl && (
                  <>
                    {qr?.url === selectedUrl && (
                      <img
                        className="enrollment-qr"
                        src={qr.image}
                        alt={`QR code for enrollment ${selected?.number}`}
                      />
                    )}
                    <a
                      className="join-link"
                      href={selectedUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {selectedUrl}
                    </a>
                  </>
                )}
                <div className="actions">
                  {selectedUrl && (
                    <button
                      type="button"
                      className="secondary"
                      onClick={() =>
                        void navigator.clipboard
                          .writeText(selectedUrl)
                          .then(() =>
                            setMessage(
                              "Enrollment link copied. Share it privately.",
                            ),
                          )
                          .catch(() =>
                            setMessage("Select and copy the link above."),
                          )
                      }
                    >
                      Copy selected link
                    </button>
                  )}
                  <button
                    type="button"
                    className="secondary"
                    onClick={downloadCsv}
                  >
                    Download CSV
                  </button>
                  <button type="button" className="secondary" onClick={dismiss}>
                    Hide displayed tokens
                  </button>
                </div>
              </div>
            )}
            {message && <p role="status">{message}</p>}
          </section>
          <section className="panel credential-panel">
            <h2>Enrollment links</h2>
            {enrollments.length === 0 ? (
              <p>No enrollment links have been issued.</p>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Number</th>
                      <th>Created</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {enrollments.map((item) => (
                      <tr key={item.id}>
                        <td>{item.number}</td>
                        <td>{new Date(item.createdAt).toLocaleString()}</td>
                        <td>{item.status}</td>
                        <td>
                          {item.status === "available" && group.available ? (
                            <button
                              className="secondary"
                              disabled={busy}
                              onClick={() => void revoke(item.id)}
                            >
                              Revoke unused link
                            </button>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
