import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { PublicRoom } from '../shared/rooms.js';
import { WORKSHOP_PROOF_VERSION } from '../shared/workshopProof.js';
import { ApiError, api, requestFix } from './api.js';
import { WorkshopAdmission } from './WorkshopAdmission.js';
import {
  generateWorkshopProof,
  submitProofWithBusyRetry,
  type ProofRule,
  type WorkshopChallenge,
} from './workshopProof.js';
import { loadGroupCredentialState, type GroupCredential } from './groupCredentialStore.js';

interface ReusableAdmissionProps {
  room: PublicRoom;
  code: string;
  onAdmitted: () => void;
}

export function ReusableAdmission({ room, code, onAdmitted }: ReusableAdmissionProps) {
  const [rule, setRule] = useState<ProofRule | null | undefined>(undefined);
  const [credentials, setCredentials] = useState<GroupCredential[]>([]);
  const [credentialError, setCredentialError] = useState('');
  const [ruleError, setRuleError] = useState('');
  const [loading, setLoading] = useState(true);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [groupSize, setGroupSize] = useState<number | null>(null);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    let active = true;
    const ruleRequest = api<{ proofRule: ProofRule | null }>(`/join/${code}/proof-rule`)
      .then(value => {
        if (!active) return;
        setRule(value.proofRule);
        setRuleError('');
      })
      .catch(cause => {
        if (active) setRuleError(cause instanceof Error ? cause.message : 'Unable to load this room’s credential rule.');
      });
    const credentialRequest = loadGroupCredentialState()
      .then(state => {
        if (!active) return;
        setCredentials(state.credentials);
        setCredentialError(state.damaged.length > 0
          ? 'One or more saved credentials are damaged. Other readable credentials can still be used; open My credentials to reset a selected damaged record.'
          : '');
      })
      .catch(cause => {
        if (active) setCredentialError(cause instanceof Error ? cause.message : 'Unable to read local credentials.');
      });
    void Promise.all([ruleRequest, credentialRequest]).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
      controller.current?.abort();
    };
  }, [code]);

  async function prove(event: FormEvent) {
    event.preventDefault();
    if (!rule) return;
    setBusy(true);
    setError('');
    const abortController = new AbortController();
    controller.current = abortController;
    try {
      const challenge = await api<WorkshopChallenge>(
        `/join/${code}/proof-challenge`,
        'POST',
        {},
        abortController.signal,
      );
      setGroupSize(challenge.commitments.length);
      if (challenge.version !== WORKSHOP_PROOF_VERSION
          || challenge.proofRule?.digest !== rule.digest
          || Date.parse(challenge.expiresAt) <= Date.now()) {
        throw new Error('This credential rule changed or the proof challenge expired. Refresh and try again.');
      }

      const allowedGroups = new Set(rule.groups.map(group => group.id.toLowerCase()));
      const allowedCommitments = new Set(challenge.commitments);
      const local = credentials
        .filter(credential => !credential.pending
          && allowedGroups.has(credential.groupId.toLowerCase())
          && allowedCommitments.has(credential.commitment))
        .sort((a, b) => a.groupId.localeCompare(b.groupId))[0];
      if (!local) {
        throw new Error('This browser has no enrolled credential from the groups accepted by this room. Ask the organizer for an enrollment link, save that credential, then return here.');
      }

      const proof = await generateWorkshopProof(local.privateKey, challenge, abortController.signal);
      const location = room.geo ? await requestFix() : null;
      const body: Record<string, unknown> = { challengeId: challenge.challengeId, proof };
      if (label.trim()) body.label = label.trim();
      if (location) Object.assign(body, location);
      await submitProofWithBusyRetry(code, body, abortController.signal, Date.parse(challenge.expiresAt));
      onAdmitted();
    } catch (cause) {
      setError(cause instanceof ApiError && cause.code === 'ADMISSION_DENIED'
        ? cause.message
        : cause instanceof Error
          ? cause.message
          : 'Unable to prove membership.');
    } finally {
      controller.current = null;
      setBusy(false);
    }
  }

  if (loading) return <p role="status">Checking this browser for a saved credential…</p>;
  if (ruleError) return <p role="alert" className="error">{ruleError}</p>;
  if (!rule) return <WorkshopAdmission room={room} code={code} onAdmitted={onAdmitted} />;

  const labels = rule.groups.map(group => group.name);
  const acceptedGroupNames = labels.length === 1
    ? labels[0]
    : `${labels.slice(0, -1).join(', ')} or ${labels.at(-1)}`;
  const matching = credentials.filter(item => !item.pending
    && rule.groups.some(group => group.id.toLowerCase() === item.groupId.toLowerCase()));
  const pendingMatching = credentials.some(item => item.pending
    && rule.groups.some(group => group.id.toLowerCase() === item.groupId.toLowerCase()));

  return (
    <section className="workshop-admission" aria-labelledby="reusable-admission-title">
      <h2 id="reusable-admission-title">Credential group proof</h2>
      <p>This room accepts a credential from {acceptedGroupNames}.</p>
      <p className="muted">The proof does not name which group qualifies. The organizer can see group rosters and enrollment activity; browser and network activity can still be linked. A small or exclusive group offers little privacy.</p>
      {error && <p role="alert" className="error">{error}</p>}
      {credentialError && <p role="alert" className="error">{credentialError}</p>}
      {groupSize !== null && groupSize < 3 && (
        <p className="muted">Only {groupSize} enrolled credentials are accepted by this rule, so this group set offers little cover.</p>
      )}
      {matching.length === 0 ? (
        <p>
          {pendingMatching
            ? 'This browser has a credential whose enrollment is not confirmed. Reopen the same organizer link to retry enrollment.'
            : 'This browser has no saved credential from the accepted groups. Ask the organizer for a single use enrollment link. The room link alone cannot enroll you.'}
        </p>
      ) : (
        <form onSubmit={event => void prove(event)}>
          <label>
            Nickname (optional)
            <input maxLength={50} value={label} onChange={event => setLabel(event.target.value)} placeholder="Room participant" />
          </label>
          <button disabled={busy}>
            {busy ? 'Checking membership…' : room.geo ? 'Share location and prove membership' : 'Prove membership and enter'}
          </button>
        </form>
      )}
      {room.geo && <p className="muted">This room checks your device location during admission. Your coordinates are sent with the proof request.</p>}
      <p className="muted">Several saved credentials can represent distinct browser identities and enter separately. Proofs do not establish one person per credential.</p>
    </section>
  );
}
