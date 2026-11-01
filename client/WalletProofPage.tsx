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
    adapter: string;
    proofDepth: number | null;
    adapterConfig: { publicSignalNames: string[]; fingerprint: string; nPublic: number } | null;
  };
  expiresAt: string;
}
interface CustomChallenge {
  adapter: string;
  challengeId: string;
  challenge: string;
  adapterFingerprint: string;
  expiresAt: string;
}

const BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BN254_BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]{0,76})$/;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function onlyKeys(value: Record<string, unknown>, keys: string[]) {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function parseImportedProof(text: string, config: NonNullable<Descriptor["contract"]["adapterConfig"]>, expectedChallenge: string) {
  let packet: unknown;
  try { packet = JSON.parse(text); } catch { throw new Error("Choose a valid proof JSON file or paste its JSON contents."); }
  if (!record(packet) || !onlyKeys(packet, ["proof", "publicSignals"]) || !record(packet.proof) || !onlyKeys(packet.proof, ["protocol", "curve", "pi_a", "pi_b", "pi_c"]))
    throw new Error("This is not a proof-only JSON packet. Choose the proof output, not a witness or input file; the wallet will not upload extra fields.");
  const proof = packet.proof;
  if (proof.protocol !== "groth16" || !["bn128", "bn254"].includes(String(proof.curve)))
    throw new Error("The imported proof must use the Groth16 BN254 protocol.");
  const scalar = (value: unknown) => typeof value === "string" && value.length <= 77 && CANONICAL_DECIMAL.test(value) && BigInt(value) < BN254_SCALAR_FIELD;
  const coordinate = (value: unknown) => typeof value === "string" && value.length <= 77 && CANONICAL_DECIMAL.test(value) && BigInt(value) < BN254_BASE_FIELD;
  const g1 = (value: unknown) =>
    Array.isArray(value) &&
    value.length === 3 &&
    value.every(coordinate) &&
    value[2] === "1";
  const g2 = (value: unknown) =>
    Array.isArray(value) &&
    value.length === 3 &&
    value.every(
      (item) =>
        Array.isArray(item) && item.length === 2 && item.every(coordinate),
    ) &&
    (value[2] as unknown[])[0] === "1" &&
    (value[2] as unknown[])[1] === "0";
  if (!g1(proof.pi_a) || !g2(proof.pi_b) || !g1(proof.pi_c))
    throw new Error("Proof points must be canonical affine BN254 coordinates with bounded decimal fields.");
  if (!Array.isArray(packet.publicSignals) || packet.publicSignals.length !== config.nPublic || !packet.publicSignals.every(scalar))
    throw new Error("Public signals must match the pinned key's declared count and contain canonical field decimals.");
  const publicSignals = packet.publicSignals as string[];
  if (publicSignals[0] !== expectedChallenge || publicSignals[1] !== "1" || publicSignals[2] === "0")
    throw new Error("The proof must use this challenge, show eligibility result 1, and include a nonzero nullifier.");
  return {
    proof: {
      protocol: "groth16" as const,
      curve: "bn128",
      pi_a: [...proof.pi_a as string[]],
      pi_b: (proof.pi_b as string[][]).map(point => [...point]),
      pi_c: [...proof.pi_c as string[]],
    },
    publicSignals: [...publicSignals],
  };
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
  const [customChallenge, setCustomChallenge] = useState<CustomChallenge | null>(null);
  const [customProofText, setCustomProofText] = useState("");
  const [disclosures, setDisclosures] = useState<Array<{ name: string; value: string }> | null>(null);
  const [customProofVerified, setCustomProofVerified] = useState(false);
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

  async function prepareCustomProof() {
    if (!capability || !descriptor?.contract.adapterConfig) return;
    setBusy(true);
    setError("");
    setDisclosures(null);
    setCustomProofVerified(false);
    setCustomChallenge(null);
    setNotice("");
    try {
      const result = await api<CustomChallenge>(`/platform/wallet/proof-requests/${requestId}/challenge`, "POST", { capability });
      const validChallenge =
        result.adapter === "groth16-bn254-v1" &&
        result.adapterFingerprint === descriptor.contract.adapterConfig.fingerprint &&
        CANONICAL_DECIMAL.test(result.challenge) &&
        result.challenge.length <= 77 &&
        BigInt(result.challenge) > 0n &&
        BigInt(result.challenge) < BN254_SCALAR_FIELD &&
        Date.parse(result.expiresAt) > Date.now();
      if (!validChallenge)
        throw new Error("This request has a different adapter or its challenge has expired.");
      setCustomChallenge(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not prepare proof challenge.");
    } finally {
      setBusy(false);
    }
  }

  function updateCustomProofText(value: string) {
    setCustomProofText(value);
    setError("");
    setNotice("");
    setDisclosures(null);
    if (customProofVerified || disclosures) setCustomChallenge(null);
    setCustomProofVerified(false);
  }

  async function verifyCustomProof() {
    if (!capability || !customChallenge || !descriptor?.contract.adapterConfig) return;
    setBusy(true);
    setError("");
    setDisclosures(null);
    try {
      if (Date.parse(customChallenge.expiresAt) <= Date.now()) throw new Error("This challenge expired. Prepare a new one and regenerate the proof.");
      const proof = parseImportedProof(customProofText, descriptor.contract.adapterConfig, customChallenge.challenge);
      const result = await api<{
        verified: boolean;
        disclosedSignals: Array<{ name: string; value: string }>;
      }>(
        `/platform/wallet/proof-requests/${requestId}/prove`,
        "POST",
        { capability, challengeId: customChallenge.challengeId, proof },
      );
      setDisclosures(result.disclosedSignals);
      setCustomProofVerified(true);
      setNotice("The proof is valid. Review the disclosed signals below, then choose Approve to continue.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The proof could not be checked.");
    } finally {
      setBusy(false);
    }
  }

  async function approveCustomProof() {
    if (!capability || !disclosures) return;
    setBusy(true);
    setError("");
    try {
      await api<{ approved: boolean; alreadyApproved?: boolean }>(`/platform/wallet/proof-requests/${requestId}/approve-custom-proof`, "POST", { capability });
      setDescriptor(current => current ? { ...current, status: "verified" } : current);
      setNotice("Approved. You can now return to the application.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not approve this proof.");
    } finally {
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
  const customAdapter = descriptor.contract.adapter === "groth16-bn254-v1";
  return (
    <section className="panel wallet-consent" aria-labelledby="consent-title">
      <p className="eyebrow">PORTKEY WALLET</p>
      <h1 id="consent-title">{customAdapter ? "Eligibility proof request" : "Membership check"}</h1>
      <p className="proof-action-label">{customAdapter ? "Import a locally generated Groth16 proof" : "Check eligibility with a saved credential"}</p>
      <p className="muted proof-local-note">
        {customAdapter
          ? "The issuer chose this circuit and its eligibility rule. You generate the proof on your device; Portkey verifies the imported proof and does not run a witness or circuit."
          : "Portkey checks for an eligible credential in this browser and creates the membership proof here. Your credential and proof are not sent to the application."}
      </p>
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
        <dt>Proof adapter</dt>
        <dd>
          {descriptor.contract.adapter}
          {descriptor.contract.adapterConfig
            ? ` · VK ${descriptor.contract.adapterConfig.fingerprint}`
            : ""}
        </dd>
        {customAdapter && descriptor.contract.adapterConfig && (
          <>
            <dt>Declared public signals</dt>
            <dd>
              {descriptor.contract.adapterConfig.publicSignalNames.join(", ")}
            </dd>
          </>
        )}
        {descriptor.contract.adapter === "semaphore-membership-v1" && (
          <>
            <dt>Accepted groups</dt>
            <dd>
              {descriptor.contract.groups.map((group) => group.name).join(", ")}
            </dd>
          </>
        )}
        <dt>Contract fingerprint</dt>
        <dd>
          <code>{descriptor.contract.digest}</code>
        </dd>
        <dt>Eligibility result shared</dt>
        <dd>
          {customAdapter
            ? "Eligibility result verified as yes; the relying application receives the result, while the public signals are shown to you before approval."
            : "Membership verified: yes or no"}
        </dd>
        <dt>Return address</dt>
        <dd>
          <code>{descriptor.app.redirectUri}</code>
        </dd>
        <dt>Request expires</dt>
        <dd>{new Date(descriptor.expiresAt).toLocaleString()}</dd>
      </dl>
      <p className="muted">
        {customAdapter
          ? "The relying application does not receive your proof or private witness. Portkey receives and verifies the proof packet and sees its declared public signals, including the challenge and nullifier. The packet format excludes witness and input fields."
          : "The application will not receive your name, saved credential, group choice, commitment, or proof. Portkey still sees this wallet session and network activity. Your saved credential stays on this Portkey origin."}
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
          {descriptor.contract.adapter === "groth16-bn254-v1" ? (
            <>
              <p>
                This issuer chose the circuit and its eligibility rule. Portkey
                will check your imported proof; it does not run a witness or
                circuit. Review the public signals disclosed by this proof
                before you approve.
              </p>
              {!customChallenge ? (
                <button
                  type="button"
                  disabled={busy || expired}
                  onClick={() => void prepareCustomProof()}
                >
                  Prepare proof challenge
                </button>
              ) : (
                <>
                  <label>
                    Challenge JSON
                    <textarea
                      readOnly
                      value={JSON.stringify(
                        {
                          adapter: "groth16-bn254-v1",
                          challenge: customChallenge.challenge,
                          expiresAt: customChallenge.expiresAt,
                        },
                        null,
                        2,
                      )}
                    />
                  </label>
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy || expired}
                    onClick={() => void prepareCustomProof()}
                  >
                    Prepare new challenge
                  </button>
                </>
              )}
              <label>
                Import proof JSON
                <textarea
                  disabled={busy}
                  value={customProofText}
                  onChange={(event) => updateCustomProofText(event.target.value)}
                  placeholder={'{"proof":{},"publicSignals":[]}'}
                />
              </label>
              <label>
                Or choose a local proof JSON file
                <input
                  disabled={busy}
                  type="file"
                  accept="application/json,.json"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (!file) return;
                    updateCustomProofText("");
                    if (file.size > 6 * 1024) {
                      setError("Proof JSON files must be 6 KiB or smaller.");
                      return;
                    }
                    void file
                      .text()
                      .then(updateCustomProofText)
                      .catch(() => setError("This local proof file could not be read."));
                  }}
                />
              </label>
              {disclosures && (
                <dl>
                  {disclosures.map((item) => (
                    <div key={item.name}>
                      <dt>{item.name}</dt>
                      <dd><code>{item.value}</code></dd>
                    </div>
                  ))}
                </dl>
              )}
              {customChallenge &&
                (customProofVerified ? (
                  <button
                    type="button"
                    disabled={busy || expired}
                    onClick={() => void approveCustomProof()}
                  >
                    {busy ? "Approving…" : "Approve disclosed signals and continue"}
                  </button>
                ) : (
                  <button
                    type="button"
                    disabled={busy || expired || !customProofText}
                    onClick={() => void verifyCustomProof()}
                  >
                    {busy ? "Verifying proof…" : "Verify proof and show disclosures"}
                  </button>
                ))}
            </>
          ) : <button
            type="button"
            disabled={busy || expired}
            onClick={() => void prove()}
          >
            {busy ? "Checking membership…" : "Prove membership and continue"}
          </button>}
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
