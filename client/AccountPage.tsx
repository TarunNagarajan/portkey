import { useEffect, useRef, useState } from "react";
import {
  startAuthentication,
  startRegistration,
  browserSupportsWebAuthn,
} from "@simplewebauthn/browser";
import { api, ApiError, isLocalOrigin } from "./api.js";

type Status = {
  signedIn: boolean;
  sessionExpiresAt: string | null;
  canAdopt: boolean;
  preview: {
    rooms: number;
    groups: number;
    contracts: number;
    apps: number;
  } | null;
};
type Passkey = {
  credential_id: string;
  label: string;
  device_type: string;
  backed_up: boolean;
  created_at: string;
  last_used_at: string | null;
};
type OrganizerSession = {
  id: string;
  current: boolean;
  created_at: string;
  last_used_at: string;
  expires_at: string;
};

function ensureWebAuthn() {
  if (browserSupportsWebAuthn() && window.isSecureContext) return;
  throw new Error(
    isLocalOrigin(window.location.origin)
      ? "This browser does not support passkeys. Try a current browser on localhost."
      : "Passkeys need the configured HTTPS Portkey address. Open Portkey at its secure site address, not an insecure LAN address.",
  );
}

export function AccountPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [sessions, setSessions] = useState<OrganizerSession[]>([]);
  const [adopt, setAdopt] = useState(false);
  const [label, setLabel] = useState("This device");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [showRecovery, setShowRecovery] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const recoveryDialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = recoveryDialog.current;
    if (!dialog) return;
    if (showRecovery && !dialog.open) dialog.showModal();
    else if (!showRecovery && dialog.open) dialog.close();
  }, [showRecovery]);

  async function refresh() {
    const s = await api<Status>("/account/status");
    setStatus(s);
    if (s.signedIn) {
      setPasskeys(
        (await api<{ passkeys: Passkey[] }>("/account/passkeys")).passkeys,
      );
      setSessions(
        (await api<{ sessions: OrganizerSession[] }>("/account/sessions"))
          .sessions,
      );
    } else {
      setPasskeys([]);
      setSessions([]);
    }
  }
  useEffect(() => {
    void refresh().catch((e) => setError(e.message));
  }, []);

  async function withBusy(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await action();
      await refresh();
    } catch (e) {
      if (e instanceof DOMException && e.name === "NotAllowedError")
        setError(
          "Passkey request was cancelled. You can try again when ready.",
        );
      else
        setError(
          e instanceof ApiError
            ? e.message
            : e instanceof Error
              ? e.message
              : "Could not complete this passkey request.",
        );
    } finally {
      setBusy(false);
    }
  }
  async function signup() {
    ensureWebAuthn();
    if (!adopt)
      throw new Error(
        "Confirm that you want to secure this browser’s current workspace.",
      );
    const created = await api<{
      ceremonyId: string;
      options: Parameters<typeof startRegistration>[0]["optionsJSON"];
    }>("/account/signup/options", "POST", { adopt: true });
    const response = await startRegistration({ optionsJSON: created.options });
    const result = await api<{ recoveryKey: string }>(
      "/account/signup/verify",
      "POST",
      { ceremonyId: created.ceremonyId, response, label },
    );
    setRecoveryKey(result.recoveryKey);
    setShowRecovery(true);
    setMessage(
      "Your organizer account is ready. Save the recovery key before leaving this page.",
    );
  }
  async function login() {
    ensureWebAuthn();
    const start = await api<{
      ceremonyId: string;
      options: Parameters<typeof startAuthentication>[0]["optionsJSON"];
    }>("/account/login/options", "POST", {});
    const response = await startAuthentication({ optionsJSON: start.options });
    await api("/account/login/verify", "POST", {
      ceremonyId: start.ceremonyId,
      response,
    });
    setMessage(
      "Signed in. Any unrelated guest workspace stays separate until you create an account from that browser.",
    );
  }
  async function recover() {
    ensureWebAuthn();
    setMessage(
      "Recovery replaces every old passkey and signs out every other organizer session.",
    );
    const start = await api<{
      ceremonyId: string;
      options: Parameters<typeof startRegistration>[0]["optionsJSON"];
    }>("/account/recovery/options", "POST", { recoveryKey });
    const response = await startRegistration({ optionsJSON: start.options });
    const result = await api<{ recoveryKey: string }>(
      "/account/recovery/verify",
      "POST",
      { ceremonyId: start.ceremonyId, response, label },
    );
    setRecoveryKey(result.recoveryKey);
    setShowRecovery(true);
    setMessage(
      "Access restored. Save the new recovery key; the previous key and passkeys are invalid.",
    );
  }
  async function logout() {
    await api("/account/logout", "POST", {});
    setRecoveryKey("");
    setShowRecovery(false);
    setMessage("Signed out. Sign in again to manage your secured workspace.");
  }
  async function reauthenticate() {
    ensureWebAuthn();
    const start = await api<{
      ceremonyId: string;
      options: Parameters<typeof startAuthentication>[0]["optionsJSON"];
    }>("/account/reauthenticate/options", "POST", {});
    const response = await startAuthentication({ optionsJSON: start.options });
    await api("/account/reauthenticate/verify", "POST", {
      ceremonyId: start.ceremonyId,
      response,
    });
  }
  async function removePasskey(id: string) {
    await reauthenticate();
    await api(`/account/passkeys/${encodeURIComponent(id)}`, "DELETE", {});
  }
  async function addPasskey() {
    ensureWebAuthn();
    await reauthenticate();
    const o = await api<{
      ceremonyId: string;
      options: Parameters<typeof startRegistration>[0]["optionsJSON"];
    }>("/account/passkeys/options", "POST", {});
    const response = await startRegistration({ optionsJSON: o.options });
    await api("/account/passkeys/verify", "POST", {
      ceremonyId: o.ceremonyId,
      response,
      label,
    });
  }
  async function rotateRecovery() {
    await reauthenticate();
    const r = await api<{ recoveryKey: string }>(
      "/account/recovery/rotate",
      "POST",
      {},
    );
    setRecoveryKey(r.recoveryKey);
    setShowRecovery(true);
  }
  async function revokeSession(id: string) {
    await reauthenticate();
    await api(`/account/sessions/${id}/revoke`, "POST", {});
  }
  async function copyRecovery() {
    try {
      if (!navigator.clipboard?.writeText)
        throw new Error("Clipboard access is unavailable in this browser.");
      await navigator.clipboard.writeText(recoveryKey);
      setMessage("Recovery key copied. Store it somewhere private and safe.");
    } catch {
      setError("Could not copy the recovery key. Select and copy it manually.");
    }
  }
  async function downloadRecovery() {
    const url = URL.createObjectURL(
      new Blob([recoveryKey], { type: "text/plain" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "portkey-recovery-key.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="account-page">
      <header className="page-header">
        <div>
          <p className="eyebrow">ORGANIZER ACCESS</p>
          <h1>Account</h1>
          <p>
            Passkeys keep organizer access available across browsers. Attendees
            continue to use browser sessions.
          </p>
        </div>
      </header>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="success">
          {message}
        </p>
      )}
      {!status ? (
        <p role="status">Loading account details…</p>
      ) : !status.signedIn ? (
        <div className="account-card">
          <h2>Keep organizer access</h2>
          <p>
            Guest browser sessions expire after 30 days. An organizer account
            keeps ownership of rooms, credential groups, contracts and
            applications; each sign-in lasts seven days.
          </p>
          {status.preview && (
            <p>
              This browser has {status.preview.rooms}{" "}
              {status.preview.rooms === 1 ? "room" : "rooms"},{" "}
              {status.preview.groups}{" "}
              {status.preview.groups === 1
                ? "credential group"
                : "credential groups"}
              , {status.preview.contracts}{" "}
              {status.preview.contracts === 1 ? "contract" : "contracts"} and{" "}
              {status.preview.apps}{" "}
              {status.preview.apps === 1 ? "application" : "applications"}.
            </p>
          )}
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={adopt}
              onChange={(e) => setAdopt(e.target.checked)}
              disabled={!status.canAdopt}
            />{" "}
            I want to secure this browser’s current workspace with a new
            passkey.
          </label>
          <p className="muted">
            Only this explicit signup adopts the shown workspace. Signing into
            an existing account keeps unrelated guest work separate.
          </p>
          <label>
            Passkey label{" "}
            <input
              value={label}
              maxLength={64}
              onChange={(e) => setLabel(e.target.value)}
            />
          </label>
          <div className="button-row">
            <button
              disabled={busy || !adopt || !status.canAdopt}
              onClick={() => void withBusy(signup)}
            >
              Create account with passkey
            </button>
            <button
              disabled={busy}
              className="secondary"
              onClick={() => void withBusy(login)}
            >
              Sign in with passkey
            </button>
          </div>
          <details>
            <summary>Recover an account</summary>
            <p>
              Recovery replaces all existing passkeys and signs out all other
              organizer sessions. It does not restore browser-local inbox
              decryption keys or attendee credentials.
            </p>
            <label>
              Recovery key{" "}
              <input
                type="password"
                spellCheck={false}
                autoCapitalize="off"
                autoComplete="off"
                value={recoveryKey}
                onChange={(e) => setRecoveryKey(e.target.value)}
              />
            </label>
            <button
              disabled={busy || !recoveryKey}
              onClick={() => void withBusy(recover)}
            >
              Replace passkeys
            </button>
          </details>
        </div>
      ) : (
        <div className="account-card">
          <h2>Organizer account active</h2>
          <p>
            This sign-in expires{" "}
            {status.sessionExpiresAt
              ? new Date(status.sessionExpiresAt).toLocaleString()
              : "in seven days"}
            . Your organizer ownership remains available after sign-out.
          </p>
          <h3>Passkeys</h3>
          {passkeys.map((p) => (
            <div className="passkey-row" key={p.credential_id}>
              <span>
                <strong>{p.label}</strong>
                <small>
                  {p.device_type === "multiDevice"
                    ? "Synced passkey"
                    : "Device passkey"}{" "}
                  · {p.backed_up ? "backed up" : "not backed up"}
                </small>
              </span>
              <button
                className="secondary"
                disabled={busy || passkeys.length <= 1}
                onClick={() =>
                  void withBusy(() => removePasskey(p.credential_id))
                }
              >
                Remove
              </button>
            </div>
          ))}
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void withBusy(addPasskey)}
          >
            Add passkey
          </button>
          <details>
            <summary>Recovery key</summary>
            <p>
              Keep a current recovery key offline. Account recovery does not
              restore browser-local inbox decryption keys or attendee proof
              credentials; encrypted key backup remains separate.
            </p>
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void withBusy(rotateRecovery)}
            >
              Rotate recovery key
            </button>
          </details>
          <details>
            <summary>Organizer sessions</summary>
            {sessions.map((s) => (
              <div className="passkey-row" key={s.id}>
                <span>
                  <strong>
                    {s.current ? "This browser" : "Other browser"}
                  </strong>
                  <small>
                    Last used {new Date(s.last_used_at).toLocaleString()} ·
                    expires {new Date(s.expires_at).toLocaleString()}
                  </small>
                </span>
                {!s.current && (
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => void withBusy(() => revokeSession(s.id))}
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </details>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void withBusy(logout)}
          >
            Sign out
          </button>
        </div>
      )}
      {showRecovery && recoveryKey && (
        <dialog
          ref={recoveryDialog}
          className="recovery-panel"
          aria-labelledby="recovery-title"
        >
          <h2 id="recovery-title">Save your recovery key</h2>
          <p>
            This key is shown once. Losing every passkey and this key means the
            account cannot be recovered. It does not restore browser-local inbox
            keys.
          </p>
          <code>{recoveryKey}</code>
          <div className="button-row">
            <button onClick={() => void copyRecovery()}>Copy key</button>
            <button
              className="secondary"
              onClick={() => void downloadRecovery()}
            >
              Download key
            </button>
            <button
              className="secondary"
              onClick={() => {
                setShowRecovery(false);
                setRecoveryKey("");
              }}
            >
              I saved it
            </button>
          </div>
        </dialog>
      )}
    </section>
  );
}
