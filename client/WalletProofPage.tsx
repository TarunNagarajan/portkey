import { useEffect, useRef, useState } from "react";
import { loadGroupCredentialState } from "./groupCredentialStore.js";
import { api, ApiError } from "./api.js";
import {
  generateWorkshopProof,
  type WorkshopChallenge,
} from "./workshopProof.js";

interface Descriptor {
  requestId: string;
  status: string;
  app: { name: string; origin: string; redirectUri: string };
  contract: {
    id: string;
    version: number;
    name: string;
    issuerLabel: string;
    description: string;
    digest: string;
    groups: Array<{ id: string; name: string }>;
  };
  expiresAt: string;
}

function capabilityFromFragment() {
  const values = new URLSearchParams(window.location.hash.slice(1)).getAll(
    "request",
  );
  if (values.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(values[0]))
    return null;
  const decoded = atob(
    values[0].replaceAll("-", "+").replaceAll("_", "/") + "=",
  );
  const canonical = btoa(decoded)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  return decoded.length === 32 && canonical === values[0] ? values[0] : null;
}

function clearCapability() {
  window.history.replaceState(null, "", window.location.pathname);
}

export function WalletProofPage({ requestId }: { requestId: string }) {
  const [capability] = useState(capabilityFromFragment);
  const [descriptor, setDescriptor] = useState<Descriptor | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    let active = true;
    if (!capability) {
      setError(
        "This Portkey request is invalid or has expired. Return to the application and start again.",
      );
      setLoading(false);
      return;
    }
    void api<Descriptor>(
      `/platform/wallet/proof-requests/${requestId}/lookup`,
      "POST",
      { capability },
    )
      .then((result) => {
        if (active) setDescriptor(result);
      })
      .catch((cause) => {
        if (active)
          setError(
            cause instanceof Error
              ? cause.message
              : "This request is unavailable.",
          );
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      controller.current?.abort();
    };
  }, [requestId, capability]);

  async function prove() {
    if (!capability || !descriptor) return;
    setBusy(true);
    setError("");
    setNotice("");
    const abort = new AbortController();
    controller.current = abort;
    try {
      const challenge = await api<WorkshopChallenge>(
        `/platform/wallet/proof-requests/${requestId}/challenge`,
        "POST",
        { capability },
        abort.signal,
      );
      if (
        challenge.version !== "semaphore-v4" ||
        challenge.depth !== 10 ||
        Date.parse(challenge.expiresAt) <= Date.now()
      )
        throw new Error(
          "This request expired while preparing. Start it again from the application.",
        );
      const local = await loadGroupCredentialState();
      const allowed = new Set(
        descriptor.contract.groups.map((value) => value.id.toLowerCase()),
      );
      const commitments = new Set(challenge.commitments);
      const selected = local.credentials
        .filter(
          (item) =>
            !item.pending &&
            allowed.has(item.groupId.toLowerCase()) &&
            commitments.has(item.commitment),
        )
        .sort((a, b) => a.groupId.localeCompare(b.groupId))[0];
      if (!selected)
        throw new Error(
          "This browser has no saved credential accepted by this contract. Ask the issuer for an enrollment link, save the credential, then return here.",
        );
      const proof = await generateWorkshopProof(
        selected.privateKey,
        challenge,
        abort.signal,
      );
      let attempt = 0;
      while (true) {
        if (Date.parse(challenge.expiresAt) <= Date.now())
          throw new Error(
            "This request expired while checking membership. Start it again from the application.",
          );
        try {
          await api(
            `/platform/wallet/proof-requests/${requestId}/prove`,
            "POST",
            { capability, challengeId: challenge.challengeId, proof },
            abort.signal,
          );
          break;
        } catch (cause) {
          if (
            !(cause instanceof ApiError) ||
            cause.code !== "PROOF_BUSY" ||
            attempt >= 3
          )
            throw cause;
          await new Promise<void>((resolve, reject) => {
            const timer = window.setTimeout(resolve, 300 * (attempt + 1));
            abort.signal.addEventListener(
              "abort",
              () => {
                window.clearTimeout(timer);
                reject(
                  new DOMException("Proof request cancelled.", "AbortError"),
                );
              },
              { once: true },
            );
          });
          attempt += 1;
        }
      }
      setDescriptor((current) =>
        current ? { ...current, status: "verified" } : current,
      );
      setNotice(
        "Your membership was verified. Choose Return to application to share the eligibility result.",
      );
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "The membership proof could not be checked.",
      );
    } finally {
      controller.current = null;
      setBusy(false);
    }
  }

  async function returnToApplication() {
    if (!capability) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<{ redirectUrl: string }>(
        `/platform/wallet/proof-requests/${requestId}/return`,
        "POST",
        { capability },
      );
      clearCapability();
      window.location.assign(result.redirectUrl);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not return to the application.",
      );
      setBusy(false);
    }
  }

  async function decline() {
    if (!capability) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<{ redirectUrl: string }>(
        `/platform/wallet/proof-requests/${requestId}/decline`,
        "POST",
        { capability },
      );
      clearCapability();
      window.location.assign(result.redirectUrl);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not decline this request.",
      );
      setBusy(false);
    }
  }

  if (loading) return <p role="status">Checking this request…</p>;
  if (!descriptor)
    return (
      <section className="panel" role="alert">
        <h1>Request unavailable</h1>
        <p>{error}</p>
      </section>
    );
  const expired = Date.parse(descriptor.expiresAt) <= Date.now();
  return (
    <section className="panel wallet-consent" aria-labelledby="consent-title">
      <p className="eyebrow">PORTKEY WALLET</p>
      <h1 id="consent-title">Membership check</h1>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="success" role="status">
          {notice}
        </p>
      )}
      <div className="request-origin">
        <span>Requesting application</span>
        <strong>{descriptor.app.name}</strong>
        <code>{descriptor.app.origin}</code>
      </div>
      <h2>
        {descriptor.contract.name} · version {descriptor.contract.version}
      </h2>
      <p>
        Published by <strong>{descriptor.contract.issuerLabel}</strong>. Issuer
        names are self-described.
      </p>
      <p>{descriptor.contract.description}</p>
      <dl>
        <dt>Accepted groups</dt>
        <dd>
          {descriptor.contract.groups.map((group) => group.name).join(", ")}
        </dd>
        <dt>Contract digest</dt>
        <dd>
          <code>{descriptor.contract.digest}</code>
        </dd>
        <dt>Eligibility result shared</dt>
        <dd>Membership verified: yes or no</dd>
        <dt>Return address</dt>
        <dd>
          <code>{descriptor.app.redirectUri}</code>
        </dd>
        <dt>Request expires</dt>
        <dd>{new Date(descriptor.expiresAt).toLocaleString()}</dd>
      </dl>
      <p className="muted">
        The application will not receive your name, saved credential, group
        choice, commitment, or proof. Portkey still sees this wallet session and
        network activity. Your saved credential stays on this Portkey origin.
      </p>
      {descriptor.status === "verified" ? (
        <button
          type="button"
          disabled={busy || expired}
          onClick={() => void returnToApplication()}
        >
          {busy ? "Returning…" : "Return to application"}
        </button>
      ) : (
        <div className="platform-actions">
          <button
            type="button"
            disabled={busy || expired}
            onClick={() => void prove()}
          >
            {busy ? "Checking membership…" : "Prove membership and continue"}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => void decline()}
          >
            Decline
          </button>
        </div>
      )}
      {expired && (
        <p role="alert">
          This request has expired. Start a new one from the application.
        </p>
      )}
    </section>
  );
}
