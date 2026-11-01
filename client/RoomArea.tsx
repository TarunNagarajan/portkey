import { useState } from 'react';
import type { PlaceSuggestion, Room } from '../shared/rooms.js';
import { maxRadiusM, minRadiusM } from '../shared/rooms.js';
import { deriveRadius } from '../shared/geo.js';
import { api, requestFix, searchPlaces } from './api.js';
import { Icon, formatDistance } from './ui.js';

interface DraftArea {
  lat: number;
  lng: number;
  label: string;
  radiusM: number;
  source: 'search' | 'device';
}

// A squared slider gives finer control near the small (room-scale) end.
function radiusFromSlider(position: number) {
  return Math.round(minRadiusM + (maxRadiusM - minRadiusM) * (position / 100) ** 2);
}

function sliderFromRadius(radiusM: number) {
  const ratio = (radiusM - minRadiusM) / (maxRadiusM - minRadiusM);
  return Math.round(Math.sqrt(Math.max(0, ratio)) * 100);
}

export function RoomArea({
  room,
  hasAdmitted,
  onChanged,
  onError,
}: {
  room: Room;
  hasAdmitted: boolean;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const active = room.status === 'draft' || room.status === 'open';
  const editable = active && !hasAdmitted;
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<PlaceSuggestion[]>([]);
  const [searching, setSearching] = useState(false);
  const [draft, setDraft] = useState<DraftArea | null>(null);
  const [busy, setBusy] = useState(false);

  async function search() {
    setSearching(true);
    try {
      setResults(await searchPlaces(query));
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Place search failed.');
    } finally {
      setSearching(false);
    }
  }

  async function useCurrentLocation() {
    setSearching(true);
    try {
      const fix = await requestFix({ maxAccuracyM: 1000 });
      setDraft({
        lat: fix.lat,
        lng: fix.lng,
        label: 'My current location',
        radiusM: deriveRadius(fix.accuracyM),
        source: 'device',
      });
      setResults([]);
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unable to read your location.');
    } finally {
      setSearching(false);
    }
  }

  async function apply() {
    if (!draft) return;
    setBusy(true);
    try {
      await api(`/rooms/${room.id}/geo`, 'POST', {
        lat: draft.lat,
        lng: draft.lng,
        radiusM: draft.radiusM,
        label: draft.label,
        source: draft.source,
      });
      setOpen(false);
      setDraft(null);
      setResults([]);
      setQuery('');
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unable to set the area.');
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api(`/rooms/${room.id}/geo`, 'DELETE');
      setOpen(false);
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Unable to remove the area.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel area-panel" data-ui>
      <div className="panel-heading">
        <div>
          <h2>Location restriction</h2>
          <p>Only devices physically inside the chosen area can request access or enter.</p>
        </div>
      </div>
      {room.geo ? (
        <p className="area-summary">
          <Icon name="shield" />
          Restricted to <strong>{formatDistance(room.geo.radiusM)}</strong> around{' '}
          {room.geoLabel ?? `${room.geo.lat.toFixed(3)}, ${room.geo.lng.toFixed(3)}`}.
        </p>
      ) : (
        <p className="muted">No area restriction. Anyone with the link can request access.</p>
      )}
      {editable && !open && (
        <div className="actions">
          <button className="secondary" disabled={busy} onClick={() => setOpen(true)}>
            {room.geo ? 'Change area' : 'Set an area'}
          </button>
          {room.geo && (
            <button className="secondary" disabled={busy} onClick={() => void remove()}>
              Remove area
            </button>
          )}
        </div>
      )}
      {active && hasAdmitted && (
        <p className="muted">
          The area is fixed once a participant has been admitted.
        </p>
      )}
      {editable && open && (
        <div className="area-editor">
          <label className="search-field">
            <span className="sr-only">Search for a place</span>
            <Icon name="search" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search a place, e.g. Warangal"
            />
          </label>
          <div className="actions">
            <button
              type="button"
              disabled={searching || query.trim().length < 2}
              onClick={() => void search()}
            >
              {searching ? 'Searching…' : 'Search place'}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={searching}
              onClick={() => void useCurrentLocation()}
            >
              Use my current location
            </button>
          </div>
          {results.length > 0 && (
            <ul className="place-results">
              {results.map((place, index) => (
                <li key={`${place.lat},${place.lng},${index}`}>
                  <button
                    type="button"
                    className="text-button"
                    onClick={() => {
                      setDraft({ ...place, source: 'search' });
                      setResults([]);
                    }}
                  >
                    {place.label} · ~{formatDistance(place.radiusM)}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {draft && (
            <div className="area-draft">
              <p>
                <strong>{draft.label}</strong>
                <br />
                {draft.lat.toFixed(4)}, {draft.lng.toFixed(4)}
              </p>
              <label>
                Radius: <strong>{formatDistance(draft.radiusM)}</strong>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={sliderFromRadius(draft.radiusM)}
                  onChange={(event) =>
                    setDraft({ ...draft, radiusM: radiusFromSlider(Number(event.target.value)) })
                  }
                />
              </label>
              <div className="actions">
                <button disabled={busy} onClick={() => void apply()}>
                  {busy ? 'Saving…' : 'Apply area'}
                </button>
                <button className="secondary" disabled={busy} onClick={() => setDraft(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}
          <p className="muted">
            Radius can be from {formatDistance(minRadiusM)} to {formatDistance(maxRadiusM)}. Larger
            areas approximate a whole locality or city.
          </p>
        </div>
      )}
    </section>
  );
}
