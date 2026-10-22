import { useEffect, useState } from "react";

interface PublicContract {
  contractId: string;
  version: number;
  name: string;
  issuerLabel: string;
  description: string;
  groups: Array<{ id: string; name: string }>;
  digest: string;
  adapter: string;
  proofDepth: number;
  available: boolean;
  publishedAt: string;
  portkeyOrigin: string;
}

export function PublicContractPage({
  contractId,
  version,
}: {
  contractId: string;
  version: string;
}) {
  const [contract, setContract] = useState<PublicContract | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    void fetch(`/v1/contracts/${contractId}/versions/${version}`, {
      cache: "no-store",
    })
      .then(async (response) => {
        if (!response.ok)
          throw new Error("This contract version is unavailable.");
        return response.json() as Promise<PublicContract>;
      })
      .then((value) => {
        if (active) setContract(value);
      })
      .catch((cause) => {
        if (active)
          setError(
            cause instanceof Error
              ? cause.message
              : "This contract version is unavailable.",
          );
      });
    return () => {
      active = false;
    };
  }, [contractId, version]);

  if (error)
    return (
      <section role="alert" className="error">
        <h1>Contract version unavailable</h1>
        <p>{error}</p>
      </section>
    );
  if (!contract) return <p role="status">Loading public contract…</p>;
  const manifestUrl = `/v1/contracts/${contract.contractId}/versions/${contract.version}`;

  return (
    <article className="public-contract">
      <p className="eyebrow">PUBLIC PORTKEY PROOF CONTRACT</p>
      <h1>{contract.name}</h1>
      <p>
        {contract.issuerLabel} · version {contract.version}
      </p>
      <p>{contract.description}</p>
      <p
        className={
          contract.available ? "status-pill status-active" : "status-pill"
        }
      >
        {contract.available
          ? "Available for new proof requests"
          : "Unavailable for new proof requests"}
      </p>
      <h2>Eligibility rule</h2>
      <p>
        A valid Portkey Semaphore membership proof for any one of these groups
        satisfies this contract:
      </p>
      <ul>
        {contract.groups.map((group) => (
          <li key={group.id}>{group.name}</li>
        ))}
      </ul>
      <dl>
        <dt>Proof adapter</dt>
        <dd>
          {contract.adapter}, depth {contract.proofDepth}
        </dd>
        <dt>Version digest</dt>
        <dd>
          <code>{contract.digest}</code>
        </dd>
        <dt>Published</dt>
        <dd>{new Date(contract.publishedAt).toLocaleString()}</dd>
        <dt>Portkey origin</dt>
        <dd>{contract.portkeyOrigin}</dd>
      </dl>
      <a
        className="button secondary"
        href={manifestUrl}
        download={`portkey-contract-${contract.contractId}-v${contract.version}.json`}
      >
        Download JSON manifest
      </a>
      <p className="muted">
        The issuer label is self-described. Cryptographic verification proves
        group membership according to this version; it does not establish who
        controls or validates the issuer’s records.
      </p>
    </article>
  );
}
