import { useEffect, useState } from 'react';
import type { Room } from '../shared/rooms.js';
import { api } from './api.js';
import type { ProofRule } from './workshopProof.js';

interface GroupOption {
  id: string;
  name: string;
  description: string;
  enrolledCount: number;
  available: boolean;
}

type Source = 'room' | 'groups';

interface RoomProofRuleEditorProps {
  room: Room;
  onRuleState: (configured: boolean, names: string[], ready: boolean, dirty: boolean) => void;
}

function normalizedIds(ids: string[]) {
  return [...ids].map(id => id.toLowerCase()).sort();
}

export function RoomProofRuleEditor({ room, onRuleState }: RoomProofRuleEditorProps) {
  const [groups, setGroups] = useState<GroupOption[]>([]);
  const [rule, setRule] = useState<ProofRule | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [source, setSource] = useState<Source>('room');
  const [savedSource, setSavedSource] = useState<Source>('room');
  const [savedSelected, setSavedSelected] = useState<string[]>([]);
  const [dirty, setDirty] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void Promise.all([
      api<{ groups: GroupOption[] }>('/credential-groups'),
      api<{ proofRule: ProofRule | null }>(`/rooms/${room.id}/proof-rule`),
    ]).then(([groupsResult, ruleResult]) => {
      if (!active) return;
      const savedRule = ruleResult.proofRule;
      const savedIds = savedRule?.groups.map(group => group.id) ?? [];
      const savedNames = savedRule?.groups.map(group => group.name) ?? [];
      setGroups(groupsResult.groups);
      setRule(savedRule);
      setSelected(savedIds);
      setSavedSelected(savedIds);
      setSource(savedRule ? 'groups' : 'room');
      setSavedSource(savedRule ? 'groups' : 'room');
      onRuleState(!!savedRule, savedNames, true, false);
      setError('');
      setLoaded(true);
    }).catch(cause => {
      if (!active) return;
      setError(cause instanceof Error ? cause.message : 'Unable to load the proof rule.');
      onRuleState(true, [], false, false);
    });
    return () => {
      active = false;
    };
  }, [loadAttempt, onRuleState, room.id]);

  async function save() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const value = source === 'groups'
        ? await api<{ proofRule: ProofRule }>(`/rooms/${room.id}/proof-rule`, 'PUT', { groupIds: selected })
        : await api<{ proofRule: null }>(`/rooms/${room.id}/proof-rule`, 'DELETE', {});
      const nextRule = value.proofRule;
      const nextSource: Source = nextRule ? 'groups' : 'room';
      const nextSelected = nextRule?.groups.map(group => group.id) ?? [];
      setRule(nextRule);
      setSelected(nextSelected);
      setSource(nextSource);
      setSavedSelected(nextSelected);
      setSavedSource(nextSource);
      setDirty(false);
      onRuleState(!!nextRule, nextRule?.groups.map(group => group.name) ?? [], true, false);
      setNotice('Admission source saved.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to save the admission source.');
    } finally {
      setBusy(false);
    }
  }

  function updateDraft(nextSource: Source, nextSelected: string[]) {
    const changed = nextSource !== savedSource
      || normalizedIds(nextSelected).join(',') !== normalizedIds(savedSelected).join(',');
    setDirty(changed);
    onRuleState(!!rule, rule?.groups.map(group => group.name) ?? [], true, changed);
  }

  function selectSource(value: Source) {
    setNotice('');
    const nextSelected = value === 'room'
      ? []
      : selected.length > 0
        ? selected
        : groups.length > 0
          ? [groups[0].id]
          : [];
    setSource(value);
    setSelected(nextSelected);
    updateDraft(value, nextSelected);
  }

  function toggle(id: string) {
    setNotice('');
    const nextSelected = selected.includes(id)
      ? selected.filter(value => value !== id)
      : selected.length < 4
        ? [...selected, id]
        : selected;
    setSelected(nextSelected);
    updateDraft('groups', nextSelected);
  }

  function discard() {
    setSource(savedSource);
    setSelected(savedSelected);
    setDirty(false);
    setNotice('Draft admission source discarded.');
    onRuleState(!!rule, rule?.groups.map(group => group.name) ?? [], true, false);
  }

  if (!loaded) {
    return (
      <section className="panel credential-panel">
        {error ? (
          <>
            <p role="alert" className="error">{error}</p>
            <p>The saved admission source has not been confirmed, so it cannot be changed yet.</p>
            <button type="button" className="secondary" onClick={() => {
              setError('');
              setLoadAttempt(value => value + 1);
            }}>
              Retry loading admission source
            </button>
          </>
        ) : (
          <p role="status">Loading admission source…</p>
        )}
      </section>
    );
  }

  const frozen = room.status !== 'draft';
  const selectedNames = selected
    .map(id => groups.find(group => group.id === id)?.name)
    .filter((name): name is string => Boolean(name));

  return (
    <section className="panel credential-panel" aria-labelledby="proof-rule-title">
      <h2 id="proof-rule-title">Proof room admission source</h2>
      {error && <p role="alert" className="error">{error}</p>}
      {room.status === 'draft' ? (
        <>
          <fieldset className="proof-rule-sources" disabled={frozen || busy}>
            <legend>Choose a credential source</legend>
            <label>
              <input
                type="radio"
                name={`source-${room.id}`}
                checked={source === 'room'}
                onChange={() => selectSource('room')}
              />
              Room enrollment links
            </label>
            <label>
              <input
                type="radio"
                name={`source-${room.id}`}
                checked={source === 'groups'}
                onChange={() => selectSource('groups')}
              />
              Reusable credential groups
            </label>
          </fieldset>
          {source === 'groups' && groups.length === 0 ? (
            <p>No groups yet. <a href="/credential-groups">Create a credential group</a> first.</p>
          ) : null}
          {source === 'groups' && groups.length > 0 ? (
            <div className="group-choice-list">
              {groups.map(group => (
                <label key={group.id}>
                  <input
                    type="checkbox"
                    checked={selected.includes(group.id)}
                    disabled={busy || !group.available || (!selected.includes(group.id) && selected.length >= 4)}
                    onChange={() => toggle(group.id)}
                  />
                  {group.name} · {group.enrolledCount} enrolled
                  {!group.available ? ' · unavailable' : ''}
                </label>
              ))}
            </div>
          ) : null}
          {source === 'groups' && (
            <p className="muted">
              A credential from {selectedNames.join(' or ') || 'a selected group'} can enter.
              The proof covers the union without naming which group qualified. Select one to four groups.
            </p>
          )}
          <button
            type="button"
            disabled={busy || (source === 'groups' && (selected.length < 1 || selected.length > 4))}
            onClick={() => void save()}
          >
            {busy ? 'Saving…' : 'Save admission source'}
          </button>
          {dirty && (
            <>
              <p className="muted">Save or discard this draft before opening the room.</p>
              <button type="button" className="secondary" disabled={busy} onClick={discard}>
                Discard changes
              </button>
            </>
          )}
        </>
      ) : (
        <>
          <p>
            {rule
              ? `A credential from ${rule.groups.map(group => group.name).join(' or ')} can enter this room.`
              : 'This room uses its own enrollment links.'}
          </p>
          <p className="muted">Admission source is frozen after the room opens.</p>
        </>
      )}
      {notice && <p role="status">{notice}</p>}
    </section>
  );
}
