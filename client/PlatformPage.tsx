import { useEffect, useState, type FormEvent } from "react";
import { api } from "./api.js";

interface Group {
  id: string;
  name: string;
  available: boolean;
}
interface Contract {
  id: string;
  name: string;
  issuer_label: string;
  created_at: string;
}
interface TrustPin {
  contract_id: string;
  contract_version: number;
}
interface AppRecord {
  id: string;
  name: string;
  origin: string;
  redirect_uris: string[];
  key_generation: number;
  disabled_at: string | null;
  domain_verified_at: string | null;
  contracts: TrustPin[];
}
interface RequestRecord {
  id: string;
  contract_id: string;
  contract_version: number;
  status: string;
  created_at: string;
  expires_at: string;
}

function domainStatus(app: AppRecord) {
  if (!app.domain_verified_at) return "Domain verification required";
  const remaining =
    Date.parse(app.domain_verified_at) + 24 * 60 * 60_000 - Date.now();
  if (!Number.isFinite(remaining) || remaining <= 0)
    return "Domain verification required";
  const minutes = Math.ceil(remaining / 60_000);
  if (minutes >= 60)
    return `Domain verified · ${Math.floor(minutes / 60)}h ${minutes % 60}m remaining`;
  return `Domain verified · ${minutes}m remaining`;
}

export function PlatformPage() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [apps, setApps] = useState<AppRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [oneTimeKey, setOneTimeKey] = useState("");
  const [domain, setDomain] = useState<{
    appId: string;
    appName: string;
    origin: string;
    challenge: string;
    url: string;
  } | null>(null);
  const [contractName, setContractName] = useState("");
  const [issuerLabel, setIssuerLabel] = useState("");
  const [description, setDescription] = useState("");
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [appName, setAppName] = useState("");
  const [appOrigin, setAppOrigin] = useState("");
  const [redirectPath, setRedirectPath] = useState("/portkey/callback");
  const [pinContract, setPinContract] = useState("");
  const [pinVersion, setPinVersion] = useState("1");
  const [history, setHistory] = useState<Record<string, RequestRecord[]>>({});
  const [historyCursors, setHistoryCursors] = useState<
    Record<string, string | null>
  >({});
  const [versionRefresh, setVersionRefresh] = useState(0);

  async function refresh() {
    const [groupResult, contractResult, appResult] = await Promise.all([
      api<{ groups: Group[] }>("/credential-groups"),
      api<{ contracts: Contract[] }>("/platform/contracts"),
      api<{ apps: AppRecord[] }>("/platform/apps"),
    ]);
    setGroups(groupResult.groups);
    setContracts(contractResult.contracts);
    setApps(appResult.apps);
  }

  useEffect(() => {
    let mounted = true;
    void refresh()
      .catch((cause) => {
        if (mounted)
          setError(
            cause instanceof Error
              ? cause.message
              : "Could not load the verification workspace.",
          );
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  async function run(label: string, action: () => Promise<void>) {
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "The change could not be saved.",
      );
    } finally {
      setBusy("");
    }
  }

  async function createContract(event: FormEvent) {
    event.preventDefault();
    await run("contract", async () => {
      await api("/platform/contracts", "POST", {
        name: contractName,
        issuerLabel,
        description,
        groupIds: selectedGroups,
      });
      setContractName("");
      setDescription("");
      setSelectedGroups([]);
      setNotice("Contract version 1 is published and ready to share.");
      await refresh();
    });
  }

  async function publishNext(event: FormEvent, contract: Contract) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    const nextDescription = String(form.get("description") ?? "");
    const nextGroups = form.getAll("groupId").map(String);
    let published = false;
    await run(`version:${contract.id}`, async () => {
      const result = await api<{ version: number }>(
        "/platform/contracts/" + contract.id + "/versions",
        "POST",
        { description: nextDescription, groupIds: nextGroups },
      );
      published = true;
      setNotice(`Contract version ${result.version} is published.`);
      setVersionRefresh((value) => value + 1);
      await refresh();
    });
    return published;
  }

  async function createApp(event: FormEvent) {
    event.preventDefault();
    await run("app", async () => {
      const normalizedOrigin = new URL(appOrigin).origin;
      const redirectUri = new URL(redirectPath, normalizedOrigin).toString();
      const result = await api<{
        id: string;
        apiKey: string;
        name: string;
        origin: string;
      }>("/platform/apps", "POST", {
        name: appName,
        origin: normalizedOrigin,
        redirectUris: [redirectUri],
      });
      setOneTimeKey(result.apiKey);
      setAppName("");
      setAppOrigin("");
      setNotice(
        `Application ${result.name} was created. Copy the server key now.`,
      );
      await refresh();
    });
  }

  async function issueDomain(app: AppRecord) {
    await run(`domain:${app.id}`, async () => {
      const challenge = await api<{ challenge: string; url: string }>(
        `/platform/apps/${app.id}/domain-challenge`,
        "POST",
        {},
      );
      setDomain({
        appId: app.id,
        appName: app.name,
        origin: app.origin,
        challenge: challenge.challenge,
        url: challenge.url,
      });
      setNotice("Host the file shown here before checking the address.");
    });
  }

  async function verifyDomain(appId: string) {
    await run(`domain:${appId}`, async () => {
      await api(`/platform/apps/${appId}/verify-domain`, "POST", {});
      const origin =
        apps.find((app) => app.id === appId)?.origin ?? "the application";
      setDomain(null);
      setNotice(`Portkey confirmed control of ${origin}.`);
      await refresh();
    });
  }

  async function trust(app: AppRecord) {
    await run(`trust:${app.id}`, async () => {
      const contracts = [
        ...app.contracts.map((pin) => ({
          contractId: pin.contract_id,
          version: pin.contract_version,
        })),
        { contractId: pinContract, version: Number(pinVersion) },
      ];
      await api(`/platform/apps/${app.id}/trust`, "PUT", { contracts });
      setNotice("The application now trusts the selected contract version.");
      await refresh();
    });
  }

  async function loadHistory(app: AppRecord) {
    await run(`history:${app.id}`, async () => {
      const result = await api<{
        requests: RequestRecord[];
        nextCursor: string | null;
      }>(`/platform/apps/${app.id}/history?limit=25`);
      setHistory((current) => ({ ...current, [app.id]: result.requests }));
      setHistoryCursors((current) => ({
        ...current,
        [app.id]: result.nextCursor,
      }));
    });
  }

  async function nextHistory(app: AppRecord) {
    const cursor = historyCursors[app.id];
    if (!cursor) return;
    await run(`history:${app.id}`, async () => {
      const result = await api<{
        requests: RequestRecord[];
        nextCursor: string | null;
      }>(
        `/platform/apps/${app.id}/history?limit=25&cursor=${encodeURIComponent(cursor)}`,
      );
      setHistory((current) => ({
        ...current,
        [app.id]: [...(current[app.id] ?? []), ...result.requests],
      }));
      setHistoryCursors((current) => ({
        ...current,
        [app.id]: result.nextCursor,
      }));
    });
  }

  async function removePin(app: AppRecord, pin: TrustPin) {
    await run(`trust:${app.id}`, async () => {
      const contracts = app.contracts
        .filter(
          (item) =>
            item.contract_id !== pin.contract_id ||
            item.contract_version !== pin.contract_version,
        )
        .map((item) => ({
          contractId: item.contract_id,
          version: item.contract_version,
        }));
      await api(`/platform/apps/${app.id}/trust`, "PUT", { contracts });
      setNotice(
        "The contract version was removed from this application trust list. In-flight requests using it will stop.",
      );
      await refresh();
    });
  }

  if (loading) return <p role="status">Loading the verification workspace…</p>;
  return (
    <section className="platform-page">
      <header className="page-header">
        <p className="eyebrow">INDEPENDENT APPLICATIONS</p>
        <h1>Verification platform</h1>
        <p>
          Publish a membership rule or connect an application to a trusted
          Portkey contract.
        </p>
      </header>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="success">
          {notice}
        </p>
      )}
      {oneTimeKey && (
        <section className="panel" aria-label="Application key">
          <h2>Copy this server key now</h2>
          <p>
            This key is shown once. Keep it in your server’s environment and
            never put it in a browser page.
          </p>
          <code className="secret-key">{oneTimeKey}</code>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard.writeText(oneTimeKey);
            }}
          >
            Copy key
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setOneTimeKey("")}
          >
            I saved the key
          </button>
        </section>
      )}
      {domain && (
        <section className="panel">
          <h2>Verify {domain.appName}</h2>
          <p>
            Host this exact JSON at <code>{domain.url}</code>, then return here
            and check again.
          </p>
          <pre>
            {JSON.stringify(
              { appId: domain.appId, challenge: domain.challenge },
              null,
              2,
            )}
          </pre>
          <button
            type="button"
            disabled={busy !== ""}
            onClick={() => {
              void verifyDomain(domain.appId);
            }}
          >
            Check domain file
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setDomain(null)}
          >
            Close
          </button>
        </section>
      )}

      <div className="platform-grid">
        <section className="panel">
          <h2>Publish an issuer contract</h2>
          <p>
            Issuer labels are self-described. The contract accepts any member of
            the listed groups.
          </p>
          <form
            onSubmit={(event) => void createContract(event)}
            className="platform-form"
          >
            <label>
              Contract name
              <input
                required
                maxLength={100}
                value={contractName}
                onChange={(event) => setContractName(event.target.value)}
              />
            </label>
            <label>
              Issuer label
              <input
                required
                maxLength={100}
                value={issuerLabel}
                onChange={(event) => setIssuerLabel(event.target.value)}
              />
            </label>
            <label>
              Eligibility statement
              <textarea
                maxLength={500}
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </label>
            <fieldset>
              <legend>Accepted credential groups</legend>
              {groups.length === 0 ? (
                <p>Create a credential group first.</p>
              ) : (
                groups.map((group) => (
                  <label className="check-row" key={group.id}>
                    <input
                      type="checkbox"
                      checked={selectedGroups.includes(group.id)}
                      onChange={(event) =>
                        setSelectedGroups((current) =>
                          event.target.checked
                            ? [...current, group.id]
                            : current.filter((item) => item !== group.id),
                        )
                      }
                    />
                    {group.name}
                  </label>
                ))
              )}
            </fieldset>
            <button
              disabled={
                busy !== "" ||
                selectedGroups.length < 1 ||
                selectedGroups.length > 4
              }
            >
              {busy === "contract" ? "Publishing…" : "Publish version 1"}
            </button>
          </form>
          {contracts.map((contract) => (
            <article className="platform-item" key={contract.id}>
              <h3>{contract.name}</h3>
              <p>
                {contract.issuer_label} · <code>{contract.id}</code>
              </p>
              <ContractVersions
                contract={contract}
                groups={groups}
                busy={busy}
                refreshToken={versionRefresh}
                onPublish={publishNext}
                onRetire={async (version) =>
                  run(`retire:${contract.id}:${version}`, async () => {
                    if (
                      !window.confirm(
                        `Retire contract version ${version}? This stops new requests and any unexchanged result.`,
                      )
                    )
                      return;
                    await api(
                      `/platform/contracts/${contract.id}/versions/${version}/retire`,
                      "POST",
                      {},
                    );
                    setNotice(`Contract version ${version} retired.`);
                    setVersionRefresh((value) => value + 1);
                  })
                }
              />
            </article>
          ))}
        </section>

        <section className="panel">
          <h2>Connect an application</h2>
          <p>
            Applications use their own origin and backend. Portkey sends no
            credential to the application.
          </p>
          <form
            onSubmit={(event) => void createApp(event)}
            className="platform-form"
          >
            <label>
              Application name
              <input
                required
                maxLength={100}
                value={appName}
                onChange={(event) => setAppName(event.target.value)}
              />
            </label>
            <label>
              Application origin
              <input
                required
                placeholder="https://example.org"
                value={appOrigin}
                onChange={(event) => setAppOrigin(event.target.value)}
              />
            </label>
            <label>
              Callback path
              <input
                required
                value={redirectPath}
                onChange={(event) => setRedirectPath(event.target.value)}
              />
            </label>
            <button disabled={busy !== ""}>
              {busy === "app" ? "Creating…" : "Register application"}
            </button>
          </form>
          {apps.map((app) => (
            <article className="platform-item" key={app.id}>
              <h3>{app.name}</h3>
              <p>
                <strong>{app.origin}</strong>
                <br />
                {domainStatus(app)} · key generation {app.key_generation}
                {app.disabled_at ? " · disabled" : ""}
              </p>
              {!app.disabled_at && (
                <div className="platform-actions">
                  <button
                    type="button"
                    disabled={busy !== ""}
                    onClick={() => void issueDomain(app)}
                  >
                    Create domain check
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy !== ""}
                    onClick={() =>
                      void run(`rotate:${app.id}`, async () => {
                        if (
                          !window.confirm(
                            "Rotate this key? The current key and all pending requests will stop working immediately.",
                          )
                        )
                          return;
                        const value = await api<{ apiKey: string }>(
                          `/platform/apps/${app.id}/rotate-key`,
                          "POST",
                          {},
                        );
                        setOneTimeKey(value.apiKey);
                        setNotice(
                          "A replacement key was issued. The previous key is no longer valid.",
                        );
                        await refresh();
                      })
                    }
                  >
                    Rotate key
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy !== ""}
                    onClick={() =>
                      void run(`disable:${app.id}`, async () => {
                        if (
                          !window.confirm(
                            "Disable this application permanently? Its current key and pending requests will stop working.",
                          )
                        )
                          return;
                        await api(
                          `/platform/apps/${app.id}/disable`,
                          "POST",
                          {},
                        );
                        setNotice("Application disabled.");
                        await refresh();
                      })
                    }
                  >
                    Disable
                  </button>
                </div>
              )}
              <div className="platform-inline">
                <label>
                  Trusted contract ID
                  <input
                    value={pinContract}
                    onChange={(event) => setPinContract(event.target.value)}
                  />
                </label>
                <label>
                  Version
                  <input
                    type="number"
                    min="1"
                    value={pinVersion}
                    onChange={(event) => setPinVersion(event.target.value)}
                  />
                </label>
                <button
                  type="button"
                  disabled={!pinContract || busy !== ""}
                  onClick={() => void trust(app)}
                >
                  Trust version
                </button>
              </div>
              <div>
                <h4>Trusted versions</h4>
                {app.contracts.length ? (
                  <ul>
                    {app.contracts.map((pin) => (
                      <li key={`${pin.contract_id}:${pin.contract_version}`}>
                        <code>{pin.contract_id}</code> version{" "}
                        {pin.contract_version}{" "}
                        <button
                          type="button"
                          className="link-button"
                          disabled={busy !== ""}
                          onClick={() => void removePin(app, pin)}
                        >
                          Remove trust
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>No contract versions are trusted.</p>
                )}
              </div>
              <div className="platform-actions">
                <button
                  type="button"
                  className="secondary"
                  disabled={busy !== ""}
                  onClick={() => void loadHistory(app)}
                >
                  Show recent requests
                </button>
              </div>
              {history[app.id] && (
                <div>
                  <h4>Recent requests</h4>
                  {history[app.id].length ? (
                    <ul>
                      {history[app.id].map((item) => (
                        <li key={item.id}>
                          {item.status} · {item.contract_id} v
                          {item.contract_version} ·{" "}
                          {new Date(item.created_at).toLocaleString()}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No requests yet.</p>
                  )}
                </div>
              )}
              {historyCursors[app.id] && (
                <button
                  type="button"
                  className="secondary"
                  disabled={busy !== ""}
                  onClick={() => void nextHistory(app)}
                >
                  Load older requests
                </button>
              )}
            </article>
          ))}
        </section>
      </div>
    </section>
  );
}

function ContractVersions({
  contract,
  groups,
  busy,
  refreshToken,
  onPublish,
  onRetire,
}: {
  contract: Contract;
  groups: Group[];
  busy: string;
  refreshToken: number;
  onPublish: (event: FormEvent, contract: Contract) => Promise<boolean>;
  onRetire: (version: number) => Promise<void>;
}) {
  const [versions, setVersions] = useState<
    Array<{ version: number; digest: string; retired_at: string | null }>
  >([]);
  const [loadError, setLoadError] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let active = true;
    void api<{ versions: typeof versions }>(
      `/platform/contracts/${contract.id}/versions`,
    )
      .then((value) => {
        if (active) {
          setVersions(value.versions);
          setLoadError("");
        }
      })
      .catch((cause) => {
        if (active)
          setLoadError(
            cause instanceof Error
              ? cause.message
              : "Contract versions are unavailable.",
          );
      });
    return () => {
      active = false;
    };
  }, [contract.id, reload, refreshToken]);
  const contractUrl = `${window.location.origin}/contracts/${contract.id}/versions/`;
  return (
    <div>
      {loadError && (
        <p role="alert" className="error">
          {loadError}{" "}
          <button
            type="button"
            className="link-button"
            onClick={() => setReload((value) => value + 1)}
          >
            Try again
          </button>
        </p>
      )}
      {!loadError && (
        <ul>
          {versions.map((version) => (
            <li key={version.version}>
              Version {version.version} · <code>{version.digest}</code> ·{" "}
              {version.retired_at ? "retired" : "available"}{" "}
              <a
                href={`${contractUrl}${version.version}`}
                target="_blank"
                rel="noreferrer"
              >
                Public contract
              </a>{" "}
              ·{" "}
              <a
                href={`${window.location.origin}/v1/contracts/${contract.id}/versions/${version.version}`}
                download={`portkey-contract-${contract.id}-v${version.version}.json`}
              >
                Download manifest
              </a>{" "}
              {!version.retired_at && (
                <button
                  type="button"
                  className="link-button"
                  disabled={busy !== ""}
                  onClick={() => void onRetire(version.version)}
                >
                  Retire
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <details>
        <summary>Publish another version</summary>
        <form
          className="platform-form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            void onPublish(event, contract).then((published) => {
              if (published) form.reset();
            });
          }}
        >
          <label>
            Eligibility statement
            <textarea name="description" maxLength={500} required />
          </label>
          <fieldset>
            <legend>Accepted groups</legend>
            {groups.map((group) => (
              <label className="check-row" key={group.id}>
                <input name="groupId" type="checkbox" value={group.id} />
                {group.name}
              </label>
            ))}
          </fieldset>
          <button disabled={busy !== ""}>Publish next version</button>
        </form>
      </details>
      <p>
        Each public manifest names the accepted groups, adapter, proof depth,
        and immutable digest.
      </p>
    </div>
  );
}
